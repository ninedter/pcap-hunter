"""Job queue interface and in-process implementation."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import threading
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import pandas as pd

from app import config as C
from app.database.models import Job, JobStatus
from app.database.repository import CaseRepository
from app.pipeline.osint import enrich as osint_enrich
from app.utils.network_utils import bulk_resolve_ips, is_public_ip, pick_top_public_ips

if TYPE_CHECKING:
    from app.pipeline.runner import PipelineResult

logger = logging.getLogger(__name__)

# Wire-format warning code added by the worker when analysis persistence fails.
WARNING_PERSISTENCE_FAILED = "analysis_persistence_failed"
# Wire-format warning codes for the post-runner stages the worker runs itself.
WARNING_OSINT_NOT_CONFIGURED = "osint_not_configured"
WARNING_OSINT_FAILED = "osint_failed"
WARNING_YARA_FAILED = "yara_failed"
WARNING_LLM_NOT_CONFIGURED = "llm_not_configured"
WARNING_LLM_FAILED = "llm_failed"
# An environment-supplied provider key was not sent because the configured base URL
# points at a different origin than the one that key was provisioned for.
WARNING_LLM_ENV_KEY_WITHHELD = "llm_env_key_withheld_base_url_changed"

OPENAI_DEFAULT_BASE_URL = "https://api.openai.com/v1"
# LM Studio ignores the key; this non-secret placeholder keeps keyless local use working.
LMSTUDIO_PLACEHOLDER_KEY = "lm-studio"

# Wire-format job error codes written by restart recovery.
ERROR_INTERRUPTED_RESTART = "interrupted_restart"
ERROR_INPUT_MISSING = "input_missing_after_restart"

# A worker refreshes its job's heartbeat on a timer for the whole run, so a
# heartbeat older than STALE_JOB_SECONDS means the worker process is gone, not
# that a long stage (OSINT, LLM) is still in progress.
HEARTBEAT_INTERVAL_SECONDS = 15.0
STALE_JOB_SECONDS = 120
JOB_SWEEP_INTERVAL_SECONDS = 60.0
# Periodic sweep only: (database, job id) -> heartbeat value seen on the previous sweep
# that found the job stale. Heartbeats are wall-clock, so right after a host suspend or
# a clock jump every healthy job looks stale until its worker ticks again; the job is
# failed only when two consecutive sweeps see it stale with an unchanged heartbeat.
_stale_observed: dict[tuple[str, str], str | None] = {}

# One id per server process lifetime. Worker children re-import this module
# under spawn/forkserver, so the dispatching parent always passes its own token
# to the worker explicitly instead of the worker deriving one.
_BOOT_ID = uuid.uuid4().hex[:12]
_process_role = os.environ.get("PCAP_HUNTER_PROCESS_ROLE", "").strip() or "local"


@dataclass(frozen=True)
class JobOwner:
    """Parsed ``role@host:pid:boot`` identity of the process holding a job."""

    role: str
    host: str
    pid: int
    boot_id: str

    @property
    def service(self) -> str:
        """Stable identity across restarts of the same service on the same host."""
        return f"{self.role}@{self.host}"


def set_process_role(role: str) -> None:
    """Name this server process ("web", "api", ...) for job ownership.

    The UI and API containers share a database *and* a pinned hostname, so the
    hostname alone cannot tell a restarted self from the other live service.
    """
    global _process_role
    cleaned = "".join(ch for ch in str(role) if ch.isalnum() or ch in "-_")
    _process_role = cleaned or "local"


def process_owner_token() -> str:
    """Owner token for jobs dispatched by this server process."""
    host = socket.gethostname().replace(":", "_").replace("@", "_") or "unknown"
    return f"{_process_role}@{host}:{os.getpid()}:{_BOOT_ID}"


def parse_owner_token(token: str | None) -> JobOwner | None:
    """Parse a stored owner token; ``None`` for legacy rows and malformed values."""
    if not token or not isinstance(token, str):
        return None
    try:
        service, pid, boot_id = token.rsplit(":", 2)
        role, host = service.split("@", 1)
        return JobOwner(role=role, host=host, pid=int(pid), boot_id=boot_id)
    except ValueError:
        return None


def _pid_alive(pid: int) -> bool:
    """Best-effort liveness probe; unknown answers count as alive (the safe side)."""
    if pid <= 0 or os.name == "nt":
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _is_previous_boot_of(owner: JobOwner, me: JobOwner) -> bool:
    """True when ``owner`` is an earlier, now dead, incarnation of this service."""
    if owner.service != me.service or (owner.pid == me.pid and owner.boot_id == me.boot_id):
        return False
    # Same pid with a different boot id is pid reuse (routine inside a
    # container); otherwise the old process must really be gone.
    return owner.pid == me.pid or not _pid_alive(owner.pid)


def _job_options(job: Job) -> dict[str, Any]:
    try:
        options = json.loads(job.options_json or "{}")
    except (TypeError, ValueError):
        return {}
    return options if isinstance(options, dict) else {}


def _load_osint_keys() -> dict[str, str]:
    """OSINT provider keys for the headless worker: saved config first, env fallback.

    Mirrors the UI seeding in app/ui/config_ui.py (saved ``cfg_*_key`` values,
    ``OTX_KEY``/``VT_KEY``/... env overrides). Empty values are dropped so the
    caller can treat an empty dict as "OSINT not configured".

    Returns:
        Provider key mapping in the shape ``app.pipeline.osint.enrich`` expects.
    """
    saved: dict = {}
    try:
        from app.utils.config_manager import get_config_manager

        saved = get_config_manager().load() or {}
    except Exception:
        logger.info("ConfigManager unavailable; falling back to env keys only")

    keys = {
        "OTX_KEY": saved.get("cfg_otx_key") or os.getenv("OTX_KEY", ""),
        "VT_KEY": saved.get("cfg_vt_key") or os.getenv("VT_KEY", ""),
        "ABUSEIPDB_KEY": saved.get("cfg_abuseipdb_key") or os.getenv("ABUSEIPDB_KEY", ""),
        "GREYNOISE_KEY": saved.get("cfg_greynoise_key") or os.getenv("GREYNOISE_KEY", ""),
        "SHODAN_KEY": saved.get("cfg_shodan_key") or os.getenv("SHODAN_KEY", ""),
    }
    return {k: v for k, v in keys.items() if v}


@dataclass
class JobSubmission:
    """Inputs needed to enqueue a pipeline run."""

    case_id: str
    pcap_path: str
    options: dict[str, Any] = field(default_factory=dict)


class JobQueue(ABC):
    """Abstract job queue. Concrete impls: InProcessJobQueue (v1)."""

    @abstractmethod
    def enqueue(self, submission: JobSubmission) -> str:
        """Enqueue a job. Returns the generated job_id."""

    @abstractmethod
    def shutdown(self, wait: bool = True) -> None:
        """Cleanly stop accepting new jobs and optionally wait for in-flight to finish."""


class EvidencePersistenceError(RuntimeError):
    """The job produced data but its evidence receipt was not safely stored."""


class QueueFullError(Exception):
    """Raised when the queue's depth cap is exceeded."""


def _sha256_file(path: str) -> str:
    """Streaming SHA-256 of a file (used for Analysis.pcap_hash)."""
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _update_manual_stage(
    repo: CaseRepository,
    job_id: str,
    stage: str,
    *,
    completed: bool = False,
    message: str | None = None,
) -> None:
    """Publish progress for worker-owned stages that run after ``run_pipeline``."""
    if completed:
        repo.complete_job_stage(job_id, stage, message)
    else:
        repo.update_job_stage(job_id, stage, 5, message)


def _json_safe_records(value: Any) -> list[dict]:
    """Convert a bounded table-like value to JSON-safe records."""
    if isinstance(value, pd.DataFrame):
        # ``to_json`` normalizes pandas/numpy scalars, timestamps, and NaN.
        return json.loads(value.to_json(orient="records", date_format="iso"))
    if isinstance(value, list):
        return json.loads(json.dumps(value, default=str))
    return []


def _run_yara_stage(result: PipelineResult, opts: dict, job_id: str, repo: CaseRepository) -> dict | None:
    """Stage 8: YARA over carved files (mirrors app/main.py); returns results, or None when skipped or failed.

    Appends to result.stages_run/warnings and touches the job heartbeat.
    """
    yara_results = None
    _update_manual_stage(repo, job_id, "YARA Scanning")
    if opts.get("do_yara", True) and result.carved_items:
        try:
            from app.pipeline.yara_scan import scan_carved_files

            rules_dir = ""
            try:
                from app.utils.config_manager import get_config_manager

                rules_dir = (get_config_manager().load() or {}).get("cfg_yara_rules_dir") or ""
            except Exception:
                logger.info("ConfigManager unavailable; using default YARA rules")
            yara_results = scan_carved_files(result.carved_items, rules_dirs=[rules_dir] if rules_dir.strip() else None)
            result.stages_run.append("yara_scan")
        except Exception:
            logger.exception("Job %s: yara stage failed", job_id)
            result.warnings.append(WARNING_YARA_FAILED)
        _update_manual_stage(repo, job_id, "YARA Scanning", completed=True, message="YARA scan complete")
    else:
        reason = "Skipped — no carved files" if opts.get("do_yara", True) else "Skipped by run settings"
        result.stages_run.append("yara_scan_skipped")
        _update_manual_stage(repo, job_id, "YARA Scanning", completed=True, message=reason)
    return yara_results


def _run_osint_stage(result: PipelineResult, opts: dict, job_id: str, repo: CaseRepository) -> dict:
    """Stage 9: OSINT enrichment + rDNS (mirrors app/main.py); returns osint data, empty when skipped or failed.

    Appends to result.stages_run/warnings and touches the job heartbeat.
    """
    osint_data: dict = {"ips": {}, "domains": {}, "ja3": {}}
    if opts.get("osint_enabled", True):
        _update_manual_stage(repo, job_id, "OSINT enrichment", message="Querying configured reputation providers")
        keys = _load_osint_keys()
        if not keys:
            result.warnings.append(WARNING_OSINT_NOT_CONFIGURED)
        else:
            try:
                feats = result.features if isinstance(result.features, dict) else {}
                arts = dict(feats.get("artifacts", {}))
                top_n = int(opts.get("osint_top_n") or 50)
                arts["ips"] = (
                    pick_top_public_ips(feats, top_n)
                    if top_n > 0
                    else [ip for ip in arts.get("ips", []) if is_public_ip(ip)]
                )
                osint_data = osint_enrich(arts, keys, dns_analysis=result.dns_analysis or None)
                osint_data = osint_data if isinstance(osint_data, dict) else {"ips": {}, "domains": {}, "ja3": {}}
                result.stages_run.append("osint")
            except Exception:
                logger.exception("Job %s: osint stage failed", job_id)
                result.warnings.append(WARNING_OSINT_FAILED)
        _update_manual_stage(repo, job_id, "OSINT enrichment", completed=True, message="Provider enrichment complete")

    # PTR lookups are capture enrichment, not a paid reputation-provider feature.
    # Run them even when OSINT is disabled or no provider keys are configured, and
    # retain results for IPs that no provider happened to return.
    try:
        feats = result.features if isinstance(result.features, dict) else {}
        all_public = [ip for ip in feats.get("artifacts", {}).get("ips", []) if is_public_ip(ip)]
        ip_records = osint_data.setdefault("ips", {})
        for ip, hostname in bulk_resolve_ips(all_public, max_workers=C.RDNS_MAX_WORKERS).items():
            hostname = str(hostname).strip().rstrip(".")
            if not hostname:
                continue
            details = ip_records.get(ip)
            if not isinstance(details, dict):
                details = {}
                ip_records[ip] = details
            details.setdefault("ptr", hostname)
    except Exception:
        logger.exception("Job %s: reverse DNS enrichment failed", job_id)
    return osint_data


def url_origin(value: str) -> tuple[str, str, int | None] | None:
    """(scheme, host, port) a credential is bound to; None if unparseable."""
    try:
        parsed = urlparse(str(value or "").strip())
        port = parsed.port
    except ValueError:
        return None
    if not parsed.scheme or not parsed.hostname:
        return None
    scheme = parsed.scheme.lower()
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    return scheme, parsed.hostname.lower(), port


def default_llm_base_url(provider: str) -> str:
    """The base URL the deployment itself configured for ``provider`` (environment, else built-in).

    Anthropic has no configurable base URL in this application and returns "".
    """
    if provider == "openai":
        return os.getenv("OPENAI_BASE_URL") or OPENAI_DEFAULT_BASE_URL
    if provider == "anthropic":
        return ""
    return os.getenv("LMSTUDIO_BASE_URL") or C.LM_BASE_URL


def _environment_llm_secret(provider: str) -> str:
    if provider == "openai":
        return os.getenv("OPENAI_API_KEY", "").strip()
    if provider == "anthropic":
        return os.getenv("ANTHROPIC_API_KEY", "").strip()
    value = (os.getenv("LMSTUDIO_API_KEY") or C.LM_API_KEY or "").strip()
    return "" if value == LMSTUDIO_PLACEHOLDER_KEY else value


def resolve_llm_api_key(provider: str, base_url: str, stored_key: str | None) -> tuple[str, str | None]:
    """Pick the credential that may be sent to ``base_url``; shared by the worker and model discovery.

    A stored key was saved for its destination (the settings route clears it when the
    base URL moves to another origin) and is used as is. An environment-supplied key
    was provisioned for the deployment's own endpoint, so it is used only when the
    effective base URL has the same origin as the environment-configured (or built-in
    default) base URL of that provider. Otherwise no secret is sent. Anthropic has no
    user-configurable base URL, so its environment key is always eligible. LM Studio
    falls back to its non-secret placeholder so keyless local servers keep working.

    Args:
        provider: ``"lmstudio"``, ``"openai"`` or ``"anthropic"``.
        base_url: Base URL about to be called; blank means the provider default.
        stored_key: Key saved in the settings store for this provider, if any.

    Returns:
        ``(api_key, warning_code)``; the code is ``WARNING_LLM_ENV_KEY_WITHHELD``
        when an environment key existed but was withheld, else ``None``.
    """
    stored = str(stored_key or "").strip()
    fallback = LMSTUDIO_PLACEHOLDER_KEY if provider == "lmstudio" else ""
    if stored:
        return stored, None
    secret = _environment_llm_secret(provider)
    if not secret:
        return fallback, None
    if provider == "anthropic":
        return secret, None
    default_url = default_llm_base_url(provider)
    target = url_origin(str(base_url or "").strip() or default_url)
    if target is not None and target == url_origin(default_url):
        return secret, None
    return fallback, WARNING_LLM_ENV_KEY_WITHHELD


def _withheld_env_key_warning(provider: str, base_url: str, api_key: str) -> str | None:
    """Warning code when the key in use is not the environment key because it was withheld."""
    if api_key and api_key != LMSTUDIO_PLACEHOLDER_KEY:
        return None
    return resolve_llm_api_key(provider, base_url, None)[1]


def _load_llm_settings() -> tuple[str, str, str, str, str, int, bool]:
    """Load the active provider settings without putting credentials in a job row."""
    from app.llm import providers as llm_providers

    saved: dict = {}
    try:
        from app.utils.config_manager import get_config_manager

        saved = get_config_manager().load() or {}
    except Exception:
        logger.info("ConfigManager unavailable; falling back to LLM env settings")

    provider = saved.get("cfg_llm_provider") or os.getenv("LLM_PROVIDER", C.LLM_PROVIDER_DEFAULT)
    if provider not in llm_providers.PROVIDERS:
        provider = C.LLM_PROVIDER_DEFAULT

    if provider == llm_providers.PROVIDER_OPENAI:
        base_url = saved.get("cfg_openai_base_url") or os.getenv("OPENAI_BASE_URL", "")
        api_key, withheld = resolve_llm_api_key(provider, base_url, saved.get("cfg_openai_cloud_key"))
        model = saved.get("cfg_openai_model") or os.getenv("OPENAI_MODEL", C.OPENAI_MODEL_DEFAULT)
    elif provider == llm_providers.PROVIDER_ANTHROPIC:
        base_url = ""
        api_key, withheld = resolve_llm_api_key(provider, base_url, saved.get("cfg_anthropic_key"))
        model = saved.get("cfg_anthropic_model") or os.getenv("ANTHROPIC_MODEL", C.ANTHROPIC_MODEL_DEFAULT)
    else:
        base_url = saved.get("cfg_llm_endpoint") or default_llm_base_url(provider)
        api_key, withheld = resolve_llm_api_key(provider, base_url, saved.get("cfg_openai_key"))
        model = saved.get("cfg_llm_model") or os.getenv("LMSTUDIO_MODEL", C.LM_MODEL)
    if withheld:
        logger.warning(
            "The %s environment API key was not used: the configured base URL is not the origin it was "
            "provisioned for. Save a key for that URL in settings.",
            provider,
        )

    language = saved.get("cfg_llm_language") or os.getenv("LMSTUDIO_LANGUAGE", C.LM_LANGUAGE)
    from app.llm.context_window import normalize_context_window

    context_window = normalize_context_window(
        saved.get("cfg_llm_context_window") or os.getenv("LLM_CONTEXT_WINDOW", C.LLM_CONTEXT_WINDOW_DEFAULT)
    )
    unlimited_value = saved.get("cfg_llm_unlimited_context") or os.getenv("LLM_UNLIMITED_CONTEXT", "")
    unlimited_context = (
        unlimited_value
        if isinstance(unlimited_value, bool)
        else str(unlimited_value).strip().lower() in {"1", "true", "yes", "on"}
    )
    return provider, base_url, api_key, model, language, context_window, unlimited_context


def _run_llm_stage(
    result: PipelineResult,
    opts: dict,
    job_id: str,
    repo: CaseRepository,
    osint_data: dict,
    yara_results: dict | None,
) -> None:
    """Stage 10: generate the narrative in the worker so browser stops cannot discard it."""
    # API submissions historically did not run an LLM stage; keep that contract
    # unless the caller explicitly opts in (the Streamlit durable-run path does).
    if not opts.get("llm_enabled", False):
        return

    from app.llm import providers as llm_providers

    _update_manual_stage(repo, job_id, "LLM report", message="Generating the saved threat narrative")
    provider, base_url, api_key, model, language, context_window, unlimited_context = _load_llm_settings()
    withheld = _withheld_env_key_warning(provider, base_url, api_key)
    if withheld and withheld not in result.warnings:
        logger.warning("Job %s: %s", job_id, withheld)
        result.warnings.append(withheld)
    if provider in (llm_providers.PROVIDER_OPENAI, llm_providers.PROVIDER_ANTHROPIC) and not api_key:
        result.warnings.append(WARNING_LLM_NOT_CONFIGURED)
        _update_manual_stage(repo, job_id, "LLM report", completed=True)
        return
    if not model or (provider == llm_providers.PROVIDER_LMSTUDIO and not base_url):
        result.warnings.append(WARNING_LLM_NOT_CONFIGURED)
        _update_manual_stage(repo, job_id, "LLM report", completed=True)
        return

    # Build the same deterministic post-analysis evidence used by the foreground
    # Streamlit path. Without these rows, background reports received no
    # correlations, flow anomalies, or final OSINT/YARA-aware ATT&CK mapping.
    from app.analysis.correlation import correlate_indicators
    from app.analysis.flow_analysis import detect_flow_asymmetry, detect_port_anomalies
    from app.analysis.visibility import build_capture_metrics
    from app.threat_intel.attack_mapping import ATTACKMapper

    flows = result.features.get("flows") or []
    flow_asymmetry = []
    port_anomalies = []
    try:
        if flows:
            flow_asymmetry = detect_flow_asymmetry(flows)
            port_anomalies = detect_port_anomalies(flows)
    except Exception:
        logger.exception("Job %s: flow post-analysis for LLM context failed", job_id)

    correlations = []
    try:
        correlations = correlate_indicators(
            features=result.features,
            osint=osint_data,
            beacon_df=pd.DataFrame(result.beacon_df_records),
            dns_analysis=result.dns_analysis,
            tls_analysis=result.tls_analysis,
            yara_results=yara_results,
            asymmetry_results=flow_asymmetry,
        )
    except Exception:
        logger.exception("Job %s: correlation analysis for LLM context failed", job_id)

    try:
        result.attack_mapping = (
            ATTACKMapper()
            .map_analysis(
                features=result.features,
                dns_analysis=result.dns_analysis or {},
                tls_analysis=result.tls_analysis or {},
                yara_results=yara_results or {},
                beacon_results=result.beacon_df_records,
                osint=osint_data or {},
            )
            .to_dict()
        )
    except Exception:
        logger.exception("Job %s: ATT&CK mapping for LLM context failed", job_id)

    try:
        result.capture_metrics = build_capture_metrics(
            {
                "features": result.features,
                "__total_pkts": result.packet_count,
                "dns_analysis": result.dns_analysis,
                "tls_analysis": result.tls_analysis,
                "zeek_tables": result.zeek_tables,
                "yara_results": yara_results,
                "osint": osint_data,
                "correlations": correlations,
                "pipeline_warnings": result.warnings,
            }
        )
    except Exception:
        logger.exception("Job %s: capture metrics for LLM context failed", job_id)

    ja3_analysis: dict = {}
    try:
        from app.pipeline.zeek import extract_ja3_from_zeek_tables

        _, ja3_analysis = extract_ja3_from_zeek_tables(result.zeek_log_paths)
    except Exception:
        logger.exception("Job %s: JA3 extraction for LLM context failed", job_id)

    context = {
        "features": result.features,
        "osint": osint_data,
        "zeek": {name: _json_safe_records(table) for name, table in result.zeek_tables.items()},
        "beaconing": result.beacon_df_records,
        "carved": result.carved_items,
        "packet_count": result.packet_count,
        "correlations": correlations,
        "dns_analysis": result.dns_analysis,
        "tls_analysis": result.tls_analysis,
        "yara_results": yara_results,
        "flow_asymmetry": flow_asymmetry,
        "port_anomalies": port_anomalies,
        "ja3_analysis": ja3_analysis,
        "attack_mapping": result.attack_mapping,
        "capture_metrics": result.capture_metrics,
        "pipeline_stages": result.stages_run,
        "pipeline_warnings": result.warnings,
        "rdns_map": {
            ip: data["ptr"]
            for ip, data in (osint_data or {}).get("ips", {}).items()
            if isinstance(data, dict) and data.get("ptr")
        },
        "config": {
            "limit_packets": opts.get("pyshark_packet_limit"),
            "do_pyshark": opts.get("do_pyshark", True),
            "do_zeek": opts.get("do_zeek", True),
            "do_carve": opts.get("do_carve", True),
            "pre_count": opts.get("pre_count", True),
            "osint_top_n": opts.get("osint_top_n", C.OSINT_TOP_IPS_DEFAULT),
        },
    }
    try:
        result.summary_narrative = llm_providers.synthesize_report(
            provider,
            base_url=base_url,
            api_key=api_key,
            model=model,
            context=context,
            language=language,
            context_window_tokens=context_window,
            unlimited_context=unlimited_context,
        )
        if result.summary_narrative:
            result.stages_run.append("llm")
    except Exception:
        logger.exception("Job %s: LLM stage failed", job_id)
        result.warnings.append(WARNING_LLM_FAILED)
    _update_manual_stage(repo, job_id, "LLM report", completed=True, message="Threat narrative saved")


def _persist_analysis(
    result: PipelineResult,
    job: Job,
    pcap_path: str,
    osint_data: dict,
    yara_results: dict | None,
    repo: CaseRepository,
) -> None:
    """Persist the pipeline result as an Analysis so the case completes and IOCs reach the feed.

    On success sets result.analysis_id; on failure appends WARNING_PERSISTENCE_FAILED.
    """
    # Mirrors app/ui/cases_tab.py:_quick_save_analysis. Persistence failures
    # must not lose the pipeline result -> warn, keep analysis_id None.
    from app.analysis.visibility import build_capture_metrics
    from app.database.models import Analysis
    from app.threat_intel.attack_mapping import ATTACKMapper

    try:
        mapping = ATTACKMapper().map_analysis(
            features=result.features,
            dns_analysis=result.dns_analysis or {},
            tls_analysis=result.tls_analysis or {},
            yara_results=yara_results or {},
            beacon_results=result.beacon_df_records,
            osint=osint_data or {},
        )
        result.attack_mapping = mapping.to_dict()
        result.mitre_techniques = [technique.technique_id for technique in mapping.techniques]
        result.capture_metrics = build_capture_metrics(
            {
                "features": result.features,
                "__total_pkts": result.packet_count,
                "dns_analysis": result.dns_analysis,
                "tls_analysis": result.tls_analysis,
                "zeek_tables": result.zeek_tables,
                "yara_results": yara_results,
                "osint": osint_data,
                "pipeline_warnings": result.warnings,
            }
        )
        from app.agents.provenance import capture_provenance

        analysis = Analysis(
            case_id=job.case_id,
            pcap_path=pcap_path,
            pcap_hash=_sha256_file(pcap_path),
            packet_count=result.packet_count,
            features=result.features,
            osint=osint_data or {},
            report=result.summary_narrative or "",
            yara_results=yara_results,
            dns_analysis=result.dns_analysis or None,
            tls_analysis=result.tls_analysis or None,
            attack_mapping=result.attack_mapping,
            capture_metrics=result.capture_metrics,
            session_artifacts={
                "evidence_provenance": capture_provenance(job, json.loads(job.options_json or "{}")),
                "zeek_tables": {name: _json_safe_records(table) for name, table in (result.zeek_tables or {}).items()},
                "zeek_log_paths": dict(result.zeek_log_paths or {}),
                "carved": list(result.carved_items or []),
                "beacon_records": list(result.beacon_df_records or []),
                "pipeline_warnings": list(result.warnings),
                "pipeline_stages": list(result.stages_run),
                "duration_seconds": result.duration_seconds,
                "rdns_map": {
                    ip: data["ptr"]
                    for ip, data in (osint_data or {}).get("ips", {}).items()
                    if isinstance(data, dict) and data.get("ptr")
                },
            },
        )
        if result.beacon_df_records:
            analysis.features["beacon_records"] = result.beacon_df_records
        analysis.iocs = repo.extract_iocs(analysis)
        result.analysis_id = repo.save_analysis(analysis)
    except Exception:
        logger.exception("Job %s: analysis persistence failed", job.id)
        result.warnings.append(WARNING_PERSISTENCE_FAILED)


def _run_llm_report_job(job: Job, options_dict: dict, repo: CaseRepository) -> None:
    """Regenerate only a persisted analysis report without rerunning packet stages."""
    from app.pipeline.runner import PipelineResult

    analysis_id = options_dict.get("_analysis_id")
    analysis = repo.get_analysis(analysis_id) if analysis_id else None
    if analysis is None:
        raise RuntimeError("The persisted analysis for this report job could not be found.")

    artifacts = analysis.session_artifacts or {}
    result = PipelineResult(
        case_id=analysis.case_id,
        analysis_id=analysis.id,
        packet_count=analysis.packet_count,
        stages_run=list(artifacts.get("pipeline_stages") or []),
        warnings=list(artifacts.get("pipeline_warnings") or []),
        dns_analysis=analysis.dns_analysis or {},
        tls_analysis=analysis.tls_analysis or {},
        beacon_df_records=list(artifacts.get("beacon_records") or []),
        features=analysis.features or {},
        zeek_tables={
            name: pd.DataFrame.from_records(records)
            for name, records in (artifacts.get("zeek_tables") or {}).items()
            if isinstance(records, list)
        },
        zeek_log_paths=dict(artifacts.get("zeek_log_paths") or {}),
        carved_items=list(artifacts.get("carved") or []),
        attack_mapping=analysis.attack_mapping,
        capture_metrics=analysis.capture_metrics,
    )
    _run_llm_stage(result, options_dict, job.id, repo, analysis.osint or {}, analysis.yara_results)
    if result.summary_narrative:
        analysis.report = result.summary_narrative
    artifacts["pipeline_stages"] = list(result.stages_run)
    artifacts["pipeline_warnings"] = list(result.warnings)
    analysis.session_artifacts = artifacts
    repo.save_analysis(analysis)
    if not repo.complete_job(job.id, json.dumps(result.to_dict()).encode("utf-8")):
        logger.warning("Report job %s finished after it was already closed; keeping the earlier outcome", job.id)


class _JobHeartbeat:
    """Refresh a job's heartbeat from a timer thread for the whole run.

    Pipeline stages only touch the heartbeat between steps; OSINT lookups and
    LLM synthesis can legitimately run for many minutes without one. A timer
    keeps a live job fresh regardless of what stage it is in, which is what
    lets recovery treat a stale heartbeat as a dead worker.
    """

    def __init__(self, repo: CaseRepository, job_id: str, interval: float | None = None) -> None:
        self._repo = repo
        self._job_id = job_id
        self._interval = HEARTBEAT_INTERVAL_SECONDS if interval is None else interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"job-heartbeat-{job_id}", daemon=True)

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                if not self._repo.touch_job_heartbeat(self._job_id):
                    return  # job is terminal or gone; nothing left to keep alive
            except Exception:
                logger.warning("Job %s: heartbeat write failed", self._job_id, exc_info=True)

    def __enter__(self) -> _JobHeartbeat:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5)


def _worker_run(
    job_id: str,
    db_path: str,
    pcap_path: str,
    options_dict: dict,
    owner_token: str | None = None,
) -> None:
    """Top-level worker function (must be picklable for ProcessPoolExecutor).

    Args:
        job_id: Persisted job to run.
        db_path: SQLite database path (a fresh repository is opened here).
        pcap_path: Capture to analyse.
        options_dict: Raw job options.
        owner_token: Identity of the dispatching server process, recorded on
            the job so restart recovery knows whose job this is.
    """
    from app.utils.logger import get_logger

    get_logger("app")  # spawn-platform children inherit no handlers

    from app.database.models import JobStatus as JS
    from app.database.repository import CaseRepository as Repo
    from app.pipeline.progress import CallbackProgress, ProgressEvent
    from app.pipeline.runner import PipelineOptions, run_pipeline

    repo = Repo(db_path=db_path)

    # A job can be cancelled (or its row removed — the FK pragma is off, so
    # delete_case deletes child job rows explicitly, not via cascade) between
    # enqueue and execution — the submitted future still runs. Abort before
    # burning a worker slot on a dead job.
    job = repo.get_job(job_id)
    if job is None or job.status == JS.CANCELLED:
        logger.info("Job %s gone or cancelled before start; skipping", job_id)
        return

    # CAS flip closes the residual race: a cancel/delete can still land
    # between the guard above and this write. Losing the UPDATE means the
    # job is no longer queued — skip instead of resurrecting it.
    if not repo.start_job_if_queued(job_id, owner_token=owner_token):
        logger.info("Job %s no longer queued at start; skipping", job_id)
        return

    def _on_event(event: ProgressEvent) -> None:
        if event.kind == "phase_start":
            repo.update_job_stage(job_id, event.title, 0, event.message)
        elif event.kind == "phase_set":
            repo.update_job_stage(job_id, event.title, event.percent, event.message)
        elif event.kind == "phase_done":
            repo.complete_job_stage(job_id, event.title, event.message)

    progress = CallbackProgress(callback=_on_event, total_phases=10)
    options = PipelineOptions(**{k: v for k, v in options_dict.items() if k in PipelineOptions.__dataclass_fields__})

    # Terminal writes below are compare-and-set: if recovery (or a cancel)
    # already closed this job, the late outcome is dropped instead of
    # overwriting it.
    with _JobHeartbeat(repo, job_id):
        try:
            if options_dict.get("_job_type") == "llm_report":
                _run_llm_report_job(job, options_dict, repo)
                return

            result = run_pipeline(
                pcap_path=pcap_path,
                case_id=job.case_id,
                options=options,
                progress=progress,
                heartbeat=lambda: repo.touch_job_heartbeat(job_id),
            )

            opts = options_dict  # raw dict: includes keys PipelineOptions doesn't model (e.g. do_yara)
            yara_results = _run_yara_stage(result, opts, job_id, repo)
            osint_data = _run_osint_stage(result, opts, job_id, repo)
            _run_llm_stage(result, opts, job_id, repo, osint_data, yara_results)

            _persist_analysis(result, job, pcap_path, osint_data, yara_results, repo)
            if result.analysis_id is None:
                raise EvidencePersistenceError("Evidence persistence did not complete; the job cannot be marked done.")

            result_blob = json.dumps(result.to_dict()).encode("utf-8")
            if not repo.complete_job(job_id, result_blob):
                logger.warning("Job %s finished after it was already closed; keeping the earlier outcome", job_id)
        except Exception as exc:
            logger.exception("Job %s failed: %s", job_id, exc)
            code = "evidence_persistence_failed" if isinstance(exc, EvidencePersistenceError) else "pipeline_error"
            if not repo.fail_job_if_active(job_id, code, str(exc)[:500]):
                logger.warning("Job %s failed after it was already closed; keeping the earlier outcome", job_id)


class InProcessJobQueue(JobQueue):
    """ProcessPoolExecutor-backed queue using SQLite for state."""

    def __init__(self, repo: CaseRepository, max_workers: int = 2, queue_depth: int = 100) -> None:
        self._repo = repo
        self._queue_depth = queue_depth
        self._max_workers = max_workers
        self._executor = ProcessPoolExecutor(max_workers=max_workers)
        self._executor_lock = threading.Lock()
        self._redispatching = False

    def enqueue(self, submission: JobSubmission) -> str:
        active = self._repo.count_active_jobs()
        if active >= self._queue_depth:
            raise QueueFullError(f"queue full ({active}/{self._queue_depth})")

        job = Job(
            case_id=submission.case_id,
            pcap_path=submission.pcap_path,
            options_json=json.dumps(submission.options),
            owner_token=process_owner_token(),
        )
        job_id = self._repo.create_job(job)

        self.dispatch(job_id)
        return job_id

    def dispatch(self, job_id: str) -> None:
        """Schedule an already persisted job; atomic worker claim prevents duplicates."""
        job = self._repo.get_job(job_id)
        if job is not None and job.status.value == "queued":
            options = _job_options(job)
            if options.get("_agent_id"):
                from app.agents.spool import dispatch

                dispatch(job)
                return
            args = (_worker_run, job_id, str(self._repo._db_path), job.pcap_path, options, process_owner_token())
            if self._submit(args, job_id):
                self._redispatch_after_rebuild(job_id)

    def _submit(self, args: tuple, job_id: str) -> bool:
        """Submit to the worker pool, rebuilding it once if it is broken.

        The rebuild and the submission happen under one lock, so a second thread
        can never submit to an executor the first one just shut down.

        Returns:
            True when the pool had to be rebuilt for this submission.
        """
        with self._executor_lock:
            try:
                self._executor.submit(*args)
                return False
            except BrokenProcessPool:
                # A worker that was killed (e.g. out of memory) poisons the whole
                # pool; without a rebuild every later submission would fail.
                logger.warning("Worker pool was broken; rebuilding it before dispatching job %s", job_id)
                self._executor.shutdown(wait=False)
                self._executor = ProcessPoolExecutor(max_workers=self._max_workers)
                self._executor.submit(*args)
                return True

    def _redispatch_after_rebuild(self, job_id: str) -> None:
        """Hand this process's still-queued jobs to the rebuilt pool.

        Jobs that were waiting inside the dead pool were dropped with it and
        would otherwise stay ``queued`` until the next restart. A job that is
        submitted twice is harmless: the worker's start is a compare-and-set.
        """
        with self._executor_lock:
            if self._redispatching:
                return  # A nested rebuild is already covered by the pass in progress.
            self._redispatching = True
        try:
            redispatched, failed = redispatch_orphaned_queued_jobs(
                self._repo,
                lambda: self,
                owner_token=process_owner_token(),
                current_owner_only=True,
                skip_job_ids=frozenset({job_id}),
            )
            if redispatched or failed:
                logger.warning(
                    "Worker pool rebuild: re-dispatched %d queued job(s), failed %d without input", redispatched, failed
                )
        except Exception:
            logger.exception("Could not re-dispatch queued jobs after the worker pool was rebuilt")
        finally:
            with self._executor_lock:
                self._redispatching = False

    def shutdown(self, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)


def recover_stale_running_jobs(
    repo: CaseRepository,
    stale_after_seconds: int = STALE_JOB_SECONDS,
    *,
    owner_token: str | None = None,
    confirm_stale: bool = False,
) -> int:
    """Fail RUNNING jobs whose worker is provably gone. Safe to call at boot and periodically.

    A job is failed with ``interrupted_restart`` when either:

    * it is owned by an earlier incarnation of this same service (same role
      and host, a different boot) — its worker pool died with that process; or
    * its heartbeat is older than ``stale_after_seconds``. Workers refresh the
      heartbeat on a timer, so this means the worker process itself is gone.

    Jobs held by another live service (the UI and API share one database) keep
    a fresh heartbeat and are left alone. Agent jobs are owned by the offline
    launcher and are never touched here.

    Args:
        repo: Shared case repository.
        stale_after_seconds: Heartbeat age that counts as dead.
        owner_token: This process's token; enables the previous-boot rule.
        confirm_stale: Used by the periodic sweep. A stale heartbeat only fails the
            job when the previous sweep also saw it stale with the same heartbeat
            value, so a host suspend or clock jump cannot fail a healthy job whose
            worker has simply not ticked yet. The previous-boot rule stays immediate.

    Returns:
        Number of jobs moved to FAILED by this call.
    """
    me = parse_owner_token(owner_token)
    cutoff = datetime.now() - timedelta(seconds=stale_after_seconds)
    stale_ids = {job.id for job in repo.find_stale_running_jobs(stale_after_seconds=stale_after_seconds)}
    database = str(repo._db_path)
    previously = {key: value for key, value in _stale_observed.items() if key[0] == database}
    if confirm_stale:
        # Only consecutive observations count: forget everything from this database
        # and re-record below what is still stale on this sweep.
        for key in previously:
            _stale_observed.pop(key, None)
    recovered = 0
    for job in repo.list_jobs(statuses=[JobStatus.RUNNING], limit=1000):
        if _job_options(job).get("_agent_id"):
            continue  # Its offline worker and persisted spool survive API restarts.
        owner = parse_owner_token(job.owner_token)
        detail = "The service restarted with this job in flight; resubmit the PCAP to retry."
        if me is not None and owner is not None and _is_previous_boot_of(owner, me):
            failed = repo.fail_job_if_active(
                job.id,
                ERROR_INTERRUPTED_RESTART,
                detail,
                from_status=JobStatus.RUNNING,
                owner_token=job.owner_token,
            )
        elif job.id in stale_ids:
            if confirm_stale:
                observed = (database, job.id)
                heartbeat = job.heartbeat_at.isoformat() if job.heartbeat_at else None
                if observed not in previously or previously[observed] != heartbeat:
                    _stale_observed[observed] = heartbeat
                    continue  # first sighting, or the worker ticked in between
            failed = repo.fail_job_if_active(
                job.id, ERROR_INTERRUPTED_RESTART, detail, from_status=JobStatus.RUNNING, stale_before=cutoff
            )
        else:
            continue
        if failed:
            recovered += 1
            logger.warning("Recovered interrupted running job %s -> failed", job.id)
    return recovered


def _job_input_available(repo: CaseRepository, job: Job, options: dict[str, Any]) -> bool:
    """Whether a queued job still has what it needs to run."""
    if options.get("_job_type") == "llm_report":
        analysis_id = options.get("_analysis_id")
        return bool(analysis_id) and repo.analysis_exists(str(analysis_id))
    try:
        return bool(job.pcap_path) and os.path.isfile(job.pcap_path)
    except OSError:
        return False


def redispatch_orphaned_queued_jobs(
    repo: CaseRepository,
    get_queue: Callable[[], JobQueue],
    *,
    owner_token: str | None = None,
    current_owner_only: bool = False,
    skip_job_ids: frozenset[str] = frozenset(),
) -> tuple[int, int]:
    """Re-dispatch QUEUED jobs that lost their dispatcher in a restart. Call at boot.

    The in-process worker pool is not durable: jobs still waiting in it when
    the process died stay ``queued`` in the database with nothing left to run
    them. This adopts the rows that belonged to an earlier incarnation of this
    service (and legacy rows with no recorded owner), re-dispatches those whose
    input still exists, and fails the rest with ``input_missing_after_restart``.

    Rows queued by another service, by a live sibling process, or by the agent
    launcher are left alone. Adoption is a compare-and-set on the owner column
    and the worker's start is a compare-and-set on the status, so two processes
    booting together cannot run the same job twice.

    Args:
        repo: Shared case repository.
        get_queue: Lazy queue accessor; only called when something needs dispatch.
        owner_token: This process's token (defaults to ``process_owner_token()``).
        current_owner_only: Instead of adopting earlier incarnations' rows, re-dispatch
            only the rows this very process queued. Used after a worker-pool rebuild,
            when the jobs waiting in the dead pool were dropped with it.
        skip_job_ids: Jobs the caller has already dispatched itself.

    Returns:
        ``(redispatched, failed_missing_input)`` counts.
    """
    token = owner_token or process_owner_token()
    me = parse_owner_token(token)
    redispatched = failed = 0
    # Oldest first so recovered work keeps its submission order.
    for job in reversed(repo.list_jobs(statuses=[JobStatus.QUEUED], limit=1000)):
        options = _job_options(job)
        if options.get("_agent_id") or job.id in skip_job_ids:
            continue
        owner = parse_owner_token(job.owner_token)
        if current_owner_only:
            if job.owner_token != token:
                continue  # only this process's pool was rebuilt
        elif job.owner_token and (owner is None or me is None or not _is_previous_boot_of(owner, me)):
            continue  # this boot's own work, another service's, or a live sibling's
        if not _job_input_available(repo, job, options):
            if repo.fail_job_if_active(
                job.id,
                ERROR_INPUT_MISSING,
                "The service restarted before this job started and its input is no longer available; "
                "resubmit the PCAP to retry.",
                from_status=JobStatus.QUEUED,
            ):
                failed += 1
                logger.warning("Queued job %s lost its input across a restart -> failed", job.id)
            continue
        if not current_owner_only and not repo.claim_queued_job(job.id, token, expected_owner=job.owner_token):
            continue  # another booting process adopted it first
        try:
            get_queue().dispatch(job.id)
        except Exception:
            logger.exception("Could not re-dispatch queued job %s after restart", job.id)
            continue
        redispatched += 1
        logger.info("Re-dispatched queued job %s after restart", job.id)
    return redispatched, failed


def recover_jobs_at_boot(
    repo: CaseRepository,
    get_queue: Callable[[], JobQueue],
    *,
    role: str,
    stale_after_seconds: int = STALE_JOB_SECONDS,
) -> dict[str, int]:
    """Boot-time job recovery for a server process.

    Args:
        repo: Shared case repository.
        get_queue: Lazy queue accessor (the pool is only created if needed).
        role: Service name for job ownership, e.g. ``"web"`` or ``"api"``.
        stale_after_seconds: Heartbeat age that counts as dead.

    Returns:
        Counters: ``failed_running``, ``redispatched``, ``failed_missing_input``.
    """
    set_process_role(role)
    token = process_owner_token()
    failed_running = recover_stale_running_jobs(repo, stale_after_seconds, owner_token=token)
    redispatched, failed_inputs = redispatch_orphaned_queued_jobs(repo, get_queue, owner_token=token)
    stats = {"failed_running": failed_running, "redispatched": redispatched, "failed_missing_input": failed_inputs}
    if any(stats.values()):
        logger.warning("Job recovery at startup: %s", stats)
    return stats


async def job_sweep_loop(
    repo: CaseRepository,
    *,
    interval_seconds: float = JOB_SWEEP_INTERVAL_SECONDS,
    stale_after_seconds: int = STALE_JOB_SECONDS,
) -> None:
    """Periodically fail RUNNING jobs whose worker died while the service stayed up.

    The boot sweep alone misses a job interrupted moments before a fast
    restart (its heartbeat still looks fresh) and any worker killed mid-run.
    """
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            await asyncio.to_thread(
                recover_stale_running_jobs,
                repo,
                stale_after_seconds,
                owner_token=process_owner_token(),
                confirm_stale=True,
            )
        except Exception:
            logger.exception("Periodic job sweep failed")


def cancel_queued_job(repo: CaseRepository, job_id: str) -> bool:
    """Cancel a job that is still in QUEUED state. Returns True if cancelled.

    Compare-and-set: the conditional UPDATE in the repo makes this race-free
    against the worker's RUNNING flip — missing or non-queued jobs return False.
    """
    return repo.cancel_job_if_queued(job_id)
