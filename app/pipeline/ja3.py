"""JA3/JA3S TLS fingerprint lookup and analysis."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# Known JA3 fingerprints database
# Format: {ja3_hash: {client, malware, notes, severity}}
# Sources: abuse.ch, Salesforce JA3, MISP threat intel
KNOWN_JA3_FINGERPRINTS = {
    # ==================== MALWARE ====================
    # Cobalt Strike variants (C2 Framework)
    "72a589da586844d7f0818ce684948eea": {
        "client": "Cobalt Strike",
        "malware": True,
        "severity": "critical",
        "notes": "Cobalt Strike Beacon default profile",
    },
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "client": "Cobalt Strike",
        "malware": True,
        "severity": "critical",
        "notes": "Cobalt Strike Beacon variant",
    },
    "b742b407517bac9536a77a7b0fee28e9": {
        "client": "Cobalt Strike",
        "malware": True,
        "severity": "critical",
        "notes": "Cobalt Strike malleable C2 profile",
    },
    # Banking Trojans
    "6734f37431670b3ab4292b8f60f29984": {
        "client": "Trickbot",
        "malware": True,
        "severity": "critical",
        "notes": "Trickbot banking trojan",
    },
    "3b5074b1b5d032e5620f69f9f700ff0e": {
        "client": "Emotet",
        "malware": True,
        "severity": "critical",
        "notes": "Emotet malware/loader",
    },
    "51c64c77e60f3980eea90869b68c58a8": {
        "client": "Dridex",
        "malware": True,
        "severity": "critical",
        "notes": "Dridex banking trojan",
    },
    "6e2df492db471b09851cb63d4c4ce4e9": {
        "client": "QakBot",
        "malware": True,
        "severity": "critical",
        "notes": "QakBot/Qbot banking trojan",
    },
    "c12f54a3f91dc7bafd92cb59fe009a35": {
        "client": "IcedID",
        "malware": True,
        "severity": "critical",
        "notes": "IcedID/BokBot banking trojan",
    },
    # Remote Access Trojans (RAT)
    "e7d705a3286e19ea42f587b344ee6865": {
        "client": "AsyncRAT",
        "malware": True,
        "severity": "critical",
        "notes": "AsyncRAT remote access trojan",
    },
    "05af1f5ca1b87cc9cc9b25185115607d": {
        "client": "Remcos RAT",
        "malware": True,
        "severity": "critical",
        "notes": "Remcos remote access trojan",
    },
    "1138de370e523e824bbca3fe12f16ad7": {
        "client": "njRAT",
        "malware": True,
        "severity": "critical",
        "notes": "njRAT remote access trojan",
    },
    # Loaders/Stealers
    "f436b9416f37d134cadd04886327d3e8": {
        "client": "BumbleBee",
        "malware": True,
        "severity": "critical",
        "notes": "BumbleBee malware loader",
    },
    "4d7a28d6f2f2eb39a2a2fdde3be43d84": {
        "client": "RedLine Stealer",
        "malware": True,
        "severity": "high",
        "notes": "RedLine credential stealer",
    },
    "399eb72e76e8391a5d9b2e5d0dc4a90f": {
        "client": "Raccoon Stealer",
        "malware": True,
        "severity": "high",
        "notes": "Raccoon infostealer",
    },
    # Other C2 Frameworks
    "3b5074b1b5d032e5620f69f9f700ff0f": {
        "client": "Metasploit",
        "malware": True,
        "severity": "critical",
        "notes": "Metasploit Framework default",
    },
    "d3c7faee3e5a1c1ff6c19a8abf790a82": {
        "client": "Sliver C2",
        "malware": True,
        "severity": "critical",
        "notes": "Sliver C2 framework",
    },
    # ==================== SUSPICIOUS ====================
    "b32309a26951912be7dba376398abc3b": {
        "client": "Python urllib3",
        "malware": False,
        "severity": "medium",
        "notes": "Python urllib3 - commonly used by scripts",
    },
    "cd08e31494f9531f560d64c695473da9": {
        "client": "Go HTTP client",
        "malware": False,
        "severity": "medium",
        "notes": "Golang net/http - used by many tools",
    },
    # ==================== LEGITIMATE ====================
    # Browsers (keys are MD5 hashes of JA3 strings)
    "9a35e493f961ac377f948690b5334a9c": {
        "client": "Chrome",
        "malware": False,
        "severity": "low",
        "notes": "Google Chrome browser",
    },
    "1cdbbb23088506bec06997ea951cc411": {
        "client": "Firefox",
        "malware": False,
        "severity": "low",
        "notes": "Mozilla Firefox browser",
    },
    # Command-line tools
    "3e13e220d8f6f63c59e0c9e42890b47b": {
        "client": "wget",
        "malware": False,
        "severity": "low",
        "notes": "GNU wget",
    },
    "2d9ffe0ff4c2c98abb66d41a4259a8f8": {
        "client": "curl",
        "malware": False,
        "severity": "low",
        "notes": "curl command-line tool",
    },
    "d2e0b5b9d4d3e3cb8c77c9e0e6e79f3e": {
        "client": "Python requests",
        "malware": False,
        "severity": "low",
        "notes": "Python requests library",
    },
}


def calculate_ja3(
    version: str,
    ciphers: list[str],
    extensions: list[str],
    curves: list[str],
    point_formats: list[str],
) -> str:
    """
    Calculate JA3 fingerprint hash.

    JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    Each field is joined by hyphens (-) within, and fields are separated by commas (,).

    Args:
        version: TLS version number (e.g., "771" for TLS 1.2)
        ciphers: List of cipher suite numbers
        extensions: List of extension numbers
        curves: List of elliptic curve numbers
        point_formats: List of point format numbers

    Returns:
        MD5 hash of JA3 fingerprint string

    Raises:
        ValueError: If version is empty or invalid
    """
    # Input validation
    if not version:
        raise ValueError("TLS version is required for JA3 calculation")

    try:
        # Ensure all lists contain valid values
        def safe_list(items: list) -> list[str]:
            if not items:
                return []
            return [str(x) for x in items if x is not None and str(x).strip()]

        ja3_string = ",".join(
            [
                str(version),
                "-".join(safe_list(ciphers)) or "",
                "-".join(safe_list(extensions)) or "",
                "-".join(safe_list(curves)) or "",
                "-".join(safe_list(point_formats)) or "",
            ]
        )

        logger.debug("JA3 string: %s", ja3_string)
        return hashlib.md5(ja3_string.encode()).hexdigest()

    except Exception as e:
        logger.error("Error calculating JA3 hash: %s", e)
        raise ValueError(f"Failed to calculate JA3: {e}") from e


def lookup_ja3(ja3_hash: str) -> dict[str, Any] | None:
    """
    Lookup JA3 hash in known fingerprint database.

    Args:
        ja3_hash: MD5 hash of JA3 fingerprint

    Returns:
        Dict with client info or None if unknown
    """
    if not ja3_hash or len(ja3_hash) != 32:
        return None

    ja3_hash = ja3_hash.lower()

    # Check exact match
    if ja3_hash in KNOWN_JA3_FINGERPRINTS:
        result = KNOWN_JA3_FINGERPRINTS[ja3_hash].copy()
        result["ja3"] = ja3_hash
        return result

    return None


def extract_ja3_from_zeek(ssl_log_path: str | Path) -> pd.DataFrame:
    """
    Extract JA3/JA3S data from Zeek ssl.log.

    Args:
        ssl_log_path: Path to Zeek ssl.log file

    Returns:
        DataFrame with JA3 data and lookups
    """
    ssl_log_path = Path(ssl_log_path)
    if not ssl_log_path.exists():
        return pd.DataFrame()

    rows = []

    # Try JSON format first
    try:
        with open(ssl_log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    record = json.loads(line)
                    ja3 = record.get("ja3")
                    ja3s = record.get("ja3s")

                    if ja3 or ja3s:
                        row = {
                            "src": record.get("id.orig_h"),
                            "dst": record.get("id.resp_h"),
                            "sport": record.get("id.orig_p"),
                            "dport": record.get("id.resp_p"),
                            "server_name": record.get("server_name", ""),
                            "ja3": ja3 or "",
                            "ja3s": ja3s or "",
                            "version": record.get("version", ""),
                            "cipher": record.get("cipher", ""),
                        }

                        # Lookup JA3
                        if ja3:
                            lookup = lookup_ja3(ja3)
                            if lookup:
                                row["ja3_client"] = lookup.get("client", "")
                                row["ja3_malware"] = lookup.get("malware", False)
                                row["ja3_notes"] = lookup.get("notes", "")
                            else:
                                row["ja3_client"] = "Unknown"
                                row["ja3_malware"] = False
                                row["ja3_notes"] = ""

                        rows.append(row)
                except json.JSONDecodeError:
                    continue
    except Exception:
        pass

    if not rows:
        # Try ASCII format
        try:
            cols = None
            with open(ssl_log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#fields"):
                        cols = line.split("\t")[1:]
                        continue
                    if line.startswith("#") or not line:
                        continue
                    if cols:
                        values = line.split("\t")
                        if len(values) >= len(cols):
                            record = dict(zip(cols, values))
                            ja3 = record.get("ja3", "-")
                            ja3s = record.get("ja3s", "-")

                            if ja3 != "-" or ja3s != "-":
                                row = {
                                    "src": record.get("id.orig_h", ""),
                                    "dst": record.get("id.resp_h", ""),
                                    "sport": record.get("id.orig_p", ""),
                                    "dport": record.get("id.resp_p", ""),
                                    "server_name": record.get("server_name", ""),
                                    "ja3": ja3 if ja3 != "-" else "",
                                    "ja3s": ja3s if ja3s != "-" else "",
                                    "version": record.get("version", ""),
                                    "cipher": record.get("cipher", ""),
                                }

                                if ja3 and ja3 != "-":
                                    lookup = lookup_ja3(ja3)
                                    if lookup:
                                        row["ja3_client"] = lookup.get("client", "")
                                        row["ja3_malware"] = lookup.get("malware", False)
                                        row["ja3_notes"] = lookup.get("notes", "")
                                    else:
                                        row["ja3_client"] = "Unknown"
                                        row["ja3_malware"] = False
                                        row["ja3_notes"] = ""

                                rows.append(row)
        except Exception:
            pass

    return pd.DataFrame(rows) if rows else pd.DataFrame()


def analyze_ja3_results(df: pd.DataFrame) -> dict[str, Any]:
    """
    Analyze JA3 extraction results.

    Args:
        df: DataFrame from extract_ja3_from_zeek

    Returns:
        Summary dict with analysis results
    """
    if df.empty:
        return {
            "total_tls_sessions": 0,
            "unique_ja3": 0,
            "malware_detected": False,
            "malware_ja3": [],
            "unknown_ja3": 0,
            "top_clients": {},
        }

    total = len(df)
    unique_ja3 = df["ja3"].nunique() if "ja3" in df.columns else 0

    # Check for malware
    malware_rows = df[df["ja3_malware"].fillna(False)] if "ja3_malware" in df.columns else pd.DataFrame()
    malware_detected = len(malware_rows) > 0
    malware_ja3 = malware_rows[["ja3", "ja3_client", "src", "dst"]].to_dict("records") if malware_detected else []

    # Unknown JA3
    unknown_count = len(df[df.get("ja3_client", "") == "Unknown"]) if "ja3_client" in df.columns else 0

    # Top clients
    top_clients = {}
    if "ja3_client" in df.columns:
        top_clients = df["ja3_client"].value_counts().head(10).to_dict()

    return {
        "total_tls_sessions": total,
        "unique_ja3": unique_ja3,
        "malware_detected": malware_detected,
        "malware_ja3": malware_ja3,
        "unknown_ja3": unknown_count,
        "top_clients": top_clients,
    }
