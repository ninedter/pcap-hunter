"""HTTP request analysis for threat detection.

Provides detection for:
- Suspicious User-Agent strings (missing UA, known scripting/scanning tools)
- Cleartext credentials (Basic-auth username observed in Zeek http.log)
- Suspicious URIs (risky file extensions, oversized URIs, raw-IP file downloads)
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

import pandas as pd

from app.config import HTTP_SUSPICIOUS_UA_TOKENS, HTTP_SUSPICIOUS_URI_LEN
from app.pipeline.state import PhaseHandle
from app.pipeline.zeek import load_zeek_any

logger = logging.getLogger(__name__)

# --- Result Limits ---
MAX_HTTP_RESULTS = 100  # Cap each result list to bound output size

# Raw dotted-quad IPv4 pattern, used by the raw-IP-host heuristic.
IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# File extensions associated with executables/scripts — risky when served over plain HTTP.
RISKY_EXTENSIONS = (".exe", ".dll", ".ps1", ".scr", ".bin")

# Values Zeek/ASCII logs use to mean "missing" for a field.
_MISSING_VALUES = {"-", "nan", "none", ""}


@dataclass
class HTTPRequest:
    """Parsed Zeek http.log record."""

    ts: float
    src: str
    dst: str
    host: str
    uri: str
    method: str
    user_agent: str
    username: str
    status_code: int


def _clean(value: Any) -> str:
    """Normalize a raw Zeek field to a stripped string; '-'/NaN/None/empty become ''."""
    if value is None:
        return ""
    text = str(value).strip()
    if text.lower() in _MISSING_VALUES:
        return ""
    return text


def _clean_int(value: Any) -> int:
    """Best-effort int parse; missing/unparseable values become 0."""
    text = _clean(value)
    if not text:
        return 0
    try:
        return int(float(text))
    except (ValueError, TypeError):
        return 0


def parse_http_log(df: pd.DataFrame) -> list[HTTPRequest]:
    """
    Parse Zeek http.log DataFrame into HTTPRequest objects.

    Uses dual-name column access (dotted Zeek names with underscore fallback)
    and is string-tolerant: ASCII-mode logs deliver every field as text, with
    "-" as the literal missing-value marker.

    Args:
        df: DataFrame from Zeek http.log

    Returns:
        List of HTTPRequest objects
    """
    records = []

    for row in df.to_dict(orient="records"):
        try:
            try:
                ts = float(row.get("ts", 0) or 0)
            except (ValueError, TypeError):
                ts = 0.0

            records.append(
                HTTPRequest(
                    ts=ts,
                    src=_clean(row.get("id.orig_h", row.get("id_orig_h", ""))),
                    dst=_clean(row.get("id.resp_h", row.get("id_resp_h", ""))),
                    host=_clean(row.get("host", "")),
                    uri=_clean(row.get("uri", "")),
                    method=_clean(row.get("method", "")),
                    user_agent=_clean(row.get("user_agent", "")),
                    username=_clean(row.get("username", "")),
                    status_code=_clean_int(row.get("status_code", "")),
                )
            )
        except (ValueError, TypeError) as e:
            logger.debug("Failed to parse HTTP record: %s", e)
            continue

    return records


def detect_suspicious_ua(req: HTTPRequest) -> str | None:
    """
    Detect a suspicious User-Agent on an HTTP request.

    Flags:
    - Empty/missing User-Agent on a request that has a Host (incomplete/scripted client)
    - User-Agent naming a known scripting/scanning tool (case-insensitive substring)

    Args:
        req: Parsed HTTP request

    Returns:
        Reason string if suspicious, else None
    """
    if not req.user_agent:
        if req.host:
            return "missing user-agent"
        return None

    ua_lower = req.user_agent.lower()
    for token in HTTP_SUSPICIOUS_UA_TOKENS:
        if token in ua_lower:
            return f"known tool user-agent ({token})"

    return None


def detect_cleartext_credentials(req: HTTPRequest) -> dict[str, str] | None:
    """
    Detect cleartext (Basic-auth) credentials on an HTTP request.

    Only the username is emitted — never the password, even if the log carried one.

    Args:
        req: Parsed HTTP request

    Returns:
        {"host", "uri", "username"} dict if credentials were seen, else None
    """
    if not req.username:
        return None
    return {"host": req.host, "uri": req.uri, "username": req.username}


def detect_suspicious_uri(req: HTTPRequest) -> str | None:
    """
    Detect a suspicious URI on an HTTP request.

    Flags:
    - Risky file extension (.exe/.dll/.ps1/.scr/.bin)
    - Very long URI (> HTTP_SUSPICIOUS_URI_LEN chars)
    - Raw IPv4 host serving what looks like a file download

    Args:
        req: Parsed HTTP request

    Returns:
        Reason string if suspicious, else None
    """
    if not req.uri:
        return None

    uri_lower = req.uri.lower()
    reasons = []

    matched_ext = next((ext for ext in RISKY_EXTENSIONS if ext in uri_lower), None)
    if matched_ext:
        reasons.append(f"risky file extension ({matched_ext})")

    if len(req.uri) > HTTP_SUSPICIOUS_URI_LEN:
        reasons.append(f"long URI ({len(req.uri)} chars)")

    if matched_ext and IPV4_PATTERN.match(req.host):
        reasons.append("raw-IP host serving file download")

    return "; ".join(reasons) if reasons else None


def analyze_http(
    zeek_tables: dict[str, pd.DataFrame],
    http_log_path: str | None = None,
    phase: PhaseHandle | None = None,
) -> dict[str, Any]:
    """
    Comprehensive HTTP request analysis from Zeek http.log.

    Args:
        zeek_tables: Dictionary of Zeek log DataFrames (row-capped, see ZEEK_TABLE_MAX_ROWS)
        http_log_path: Optional path to the on-disk http.log. When provided, the full
            uncapped log is read via load_zeek_any instead of the capped in-memory table.
        phase: PhaseHandle for progress updates

    Returns:
        Dictionary with HTTP analysis results
    """
    if phase and phase.should_skip():
        phase.done("HTTP analysis skipped.")
        return {"skipped": True}

    if phase:
        phase.set(5, "Parsing HTTP logs...")

    http_df: pd.DataFrame | None = None
    if http_log_path:
        try:
            http_df = load_zeek_any(http_log_path)
        except Exception as e:
            logger.debug("Failed to load full http.log from %s: %s", http_log_path, e)
            http_df = None

    if http_df is None:
        http_df = zeek_tables.get("http.log")

    if http_df is None:
        if phase:
            phase.done("No HTTP data available.")
        return {"skipped": True}

    if http_df.empty:
        if phase:
            phase.done("No HTTP data available.")
        return {"error": "No HTTP log data", "records": 0}

    records = parse_http_log(http_df)
    if not records:
        if phase:
            phase.done("No valid HTTP records found.")
        return {"error": "No HTTP log data", "records": 0}

    if phase:
        phase.set(30, f"Analyzing {len(records)} HTTP requests...")

    methods = Counter(r.method for r in records if r.method)
    status_codes = Counter(str(r.status_code) for r in records if r.status_code)
    unique_hosts = len({r.host for r in records if r.host})

    suspicious_uas = []
    cleartext_creds = []
    suspicious_uris = []

    total = len(records)
    for i, r in enumerate(records):
        if phase and i % 500 == 0:
            pct = 30 + int((i / total) * 50)
            phase.set(pct, f"Scanning request {i + 1}/{total}...")

        ua_reason = detect_suspicious_ua(r)
        if ua_reason:
            suspicious_uas.append({"host": r.host, "user_agent": r.user_agent, "uri": r.uri, "reason": ua_reason})

        cred = detect_cleartext_credentials(r)
        if cred:
            cleartext_creds.append(cred)

        uri_reason = detect_suspicious_uri(r)
        if uri_reason:
            suspicious_uris.append({"host": r.host, "uri": r.uri, "reason": uri_reason})

    if phase:
        phase.set(85, "Finalizing HTTP analysis...")

    result = {
        "total_requests": len(records),
        "unique_hosts": unique_hosts,
        "methods": dict(methods),
        "status_codes": dict(status_codes),
        "suspicious_user_agents": suspicious_uas[:MAX_HTTP_RESULTS],
        "cleartext_credentials": cleartext_creds[:MAX_HTTP_RESULTS],
        "suspicious_uris": suspicious_uris[:MAX_HTTP_RESULTS],
        "alerts": {
            "suspicious_ua_count": len(suspicious_uas),
            "cleartext_cred_count": len(cleartext_creds),
            "suspicious_uri_count": len(suspicious_uris),
        },
    }

    if phase:
        alerts = result["alerts"]
        alert_msg = []
        if alerts["suspicious_ua_count"]:
            alert_msg.append(f"{alerts['suspicious_ua_count']} suspicious UA")
        if alerts["cleartext_cred_count"]:
            alert_msg.append(f"{alerts['cleartext_cred_count']} cleartext creds")
        if alerts["suspicious_uri_count"]:
            alert_msg.append(f"{alerts['suspicious_uri_count']} suspicious URIs")

        summary = f"Analyzed {len(records)} HTTP requests, {unique_hosts} hosts."
        if alert_msg:
            summary += f" Alerts: {', '.join(alert_msg)}."
        phase.done(summary)

    return result
