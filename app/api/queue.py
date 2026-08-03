"""Job queue interface and in-process implementation."""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import pandas as pd

from app import config as C
from app.database.models import Job, JobStatus
from app.database.repository import CaseRepository
from app.pipeline.osint import enrich as osint_enrich
from app.utils.network_utils import bulk_resolve_ips, is_public_ipv4, pick_top_public_ips

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
                    else [ip for ip in arts.get("ips", []) if is_public_ipv4(ip)]
                )
                osint_data = osint_enrich(arts, keys)
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
        all_public = [ip for ip in feats.get("artifacts", {}).get("ips", []) if is_public_ipv4(ip)]
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
        api_key = saved.get("cfg_openai_cloud_key") or os.getenv("OPENAI_API_KEY", "")
        model = saved.get("cfg_openai_model") or os.getenv("OPENAI_MODEL", C.OPENAI_MODEL_DEFAULT)
    elif provider == llm_providers.PROVIDER_ANTHROPIC:
        base_url = ""
        api_key = saved.get("cfg_anthropic_key") or os.getenv("ANTHROPIC_API_KEY", "")
        model = saved.get("cfg_anthropic_model") or os.getenv("ANTHROPIC_MODEL", C.ANTHROPIC_MODEL_DEFAULT)
    else:
        base_url = saved.get("cfg_llm_endpoint") or os.getenv("LMSTUDIO_BASE_URL", C.LM_BASE_URL)
        api_key = saved.get("cfg_openai_key") or os.getenv("LMSTUDIO_API_KEY", C.LM_API_KEY)
        model = saved.get("cfg_llm_model") or os.getenv("LMSTUDIO_MODEL", C.LM_MODEL)

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
    repo.complete_job(job.id, json.dumps(result.to_dict()).encode("utf-8"))


def _worker_run(job_id: str, db_path: str, pcap_path: str, options_dict: dict) -> None:
    """Top-level worker function (must be picklable for ProcessPoolExecutor)."""
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
    if not repo.start_job_if_queued(job_id):
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

        result_blob = json.dumps(result.to_dict()).encode("utf-8")
        repo.complete_job(job_id, result_blob)
    except Exception as exc:
        logger.exception("Job %s failed: %s", job_id, exc)
        repo.update_job_status(
            job_id,
            JS.FAILED,
            error_code="pipeline_error",
            error_detail=str(exc)[:500],
        )


class InProcessJobQueue(JobQueue):
    """ProcessPoolExecutor-backed queue using SQLite for state."""

    def __init__(self, repo: CaseRepository, max_workers: int = 2, queue_depth: int = 100) -> None:
        self._repo = repo
        self._queue_depth = queue_depth
        self._executor = ProcessPoolExecutor(max_workers=max_workers)

    def enqueue(self, submission: JobSubmission) -> str:
        active = self._repo.count_active_jobs()
        if active >= self._queue_depth:
            raise QueueFullError(f"queue full ({active}/{self._queue_depth})")

        job = Job(
            case_id=submission.case_id,
            pcap_path=submission.pcap_path,
            options_json=json.dumps(submission.options),
        )
        job_id = self._repo.create_job(job)

        self._executor.submit(
            _worker_run,
            job_id,
            str(self._repo._db_path),
            submission.pcap_path,
            submission.options,
        )
        return job_id

    def shutdown(self, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)


def recover_stale_running_jobs(repo: CaseRepository, stale_after_seconds: int = 120) -> int:
    """Mark any RUNNING jobs with stale heartbeats as FAILED. Call at API startup."""
    stale = repo.find_stale_running_jobs(stale_after_seconds=stale_after_seconds)
    for job in stale:
        repo.update_job_status(
            job.id,
            JobStatus.FAILED,
            error_code="interrupted_restart",
            error_detail="API restarted with this job in flight; resubmit the PCAP to retry.",
        )
        logger.warning("Recovered stale running job %s -> failed", job.id)
    return len(stale)


def cancel_queued_job(repo: CaseRepository, job_id: str) -> bool:
    """Cancel a job that is still in QUEUED state. Returns True if cancelled.

    Compare-and-set: the conditional UPDATE in the repo makes this race-free
    against the worker's RUNNING flip — missing or non-queued jobs return False.
    """
    return repo.cancel_job_if_queued(job_id)
