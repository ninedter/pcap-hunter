"""Job queue interface and in-process implementation."""

from __future__ import annotations

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

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
WARNING_LLM_UNSUPPORTED = "llm_unsupported_on_api_path"


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


def _run_yara_stage(result: PipelineResult, opts: dict, job_id: str, repo: CaseRepository) -> dict | None:
    """Stage 8: YARA over carved files (mirrors app/main.py); returns results, or None when skipped or failed.

    Appends to result.stages_run/warnings and touches the job heartbeat.
    """
    yara_results = None
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
        repo.touch_job_heartbeat(job_id)
    return yara_results


def _run_osint_stage(result: PipelineResult, opts: dict, job_id: str, repo: CaseRepository) -> dict:
    """Stage 9: OSINT enrichment + rDNS (mirrors app/main.py); returns osint data, empty when skipped or failed.

    Appends to result.stages_run/warnings and touches the job heartbeat.
    """
    osint_data: dict = {}
    if opts.get("osint_enabled", True):
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
                osint_data = osint_data if isinstance(osint_data, dict) else {}
                all_public = [ip for ip in feats.get("artifacts", {}).get("ips", []) if is_public_ipv4(ip)]
                for ip, hostname in bulk_resolve_ips(all_public, max_workers=C.RDNS_MAX_WORKERS).items():
                    if ip in osint_data.get("ips", {}) and "ptr" not in osint_data["ips"][ip]:
                        osint_data["ips"][ip]["ptr"] = hostname
                result.stages_run.append("osint")
            except Exception:
                logger.exception("Job %s: osint stage failed", job_id)
                result.warnings.append(WARNING_OSINT_FAILED)
        repo.touch_job_heartbeat(job_id)
    return osint_data


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
    from app.database.models import Analysis

    try:
        analysis = Analysis(
            case_id=job.case_id,
            pcap_path=pcap_path,
            pcap_hash=_sha256_file(pcap_path),
            packet_count=result.packet_count,
            features=result.features,
            osint=osint_data or {},
            yara_results=yara_results,
            dns_analysis=result.dns_analysis or None,
            tls_analysis=result.tls_analysis or None,
        )
        analysis.attack_mapping = result.attack_mapping
        analysis.mitre_techniques = result.mitre_techniques
        if result.beacon_df_records:
            analysis.features["beacon_records"] = result.beacon_df_records
        if result.http_analysis:
            # Analysis has no dedicated http_analysis column — stash it in
            # features (mirroring beacon_records above); features_json is
            # compressed+persisted, and the UI restore path reads it back out.
            analysis.features["http_analysis"] = result.http_analysis
        analysis.iocs = repo.extract_iocs(analysis)
        result.analysis_id = repo.save_analysis(analysis)
    except Exception:
        logger.exception("Job %s: analysis persistence failed", job.id)
        result.warnings.append(WARNING_PERSISTENCE_FAILED)


def _dispatch_webhook(url: str, payload: dict, timeout: int, max_retries: int) -> None:
    """POST a job-completion webhook from the worker subprocess; never raises.

    Called from ``_worker_run`` on both terminal branches (done + failed).
    A webhook delivery failure must never change the job's own terminal
    state, so every failure mode here is caught and logged, not propagated.

    Re-validates the URL with ``is_safe_webhook_url`` immediately before the
    network call — defense in depth against the target becoming unsafe
    between submit-time validation (the router) and job completion (e.g. a
    DNS change). ``hardened_session`` does not itself block private IPs.

    Args:
        url: Destination webhook URL (already submit-time validated).
        payload: JSON-serializable envelope to POST.
        timeout: Per-attempt request timeout, seconds.
        max_retries: Additional attempts after the first, on non-2xx status
            or request exception.
    """
    # Every failure mode -- including the lazy imports below -- is caught by
    # this outer guard so this function NEVER raises. If it did, the
    # exception would propagate into _worker_run's `except Exception`, whose
    # unconditional `update_job_status(..., FAILED, ...)` would revert an
    # already-DONE job to FAILED. The imports live inside the try for exactly
    # that reason.
    try:
        from app.security.opsec import hardened_session, redact
        from app.utils.network_utils import is_safe_webhook_url

        if not is_safe_webhook_url(url):
            logger.warning("Webhook dispatch refused: %s no longer passes the SSRF guard", redact(url))
            return

        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        # Optional HMAC signing so the receiver can authenticate the callback.
        secret = os.environ.get("PCAP_HUNTER_API_WEBHOOK_SECRET") or None
        if secret:
            import hashlib
            import hmac

            signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-PCAP-Hunter-Signature"] = f"sha256={signature}"

        attempts = max(1, max_retries + 1)
        last_error = "unknown"
        for attempt in range(1, attempts + 1):
            try:
                # allow_redirects=False: the SSRF guard only validated `url`.
                # Following a redirect (hardened_session permits up to 3, and
                # only blocks https->http downgrades) to an attacker-chosen
                # Location -- e.g. http://169.254.169.254/ -- would reach an
                # unvalidated internal host and reopen the SSRF hole. Webhooks
                # do not need redirects.
                resp = hardened_session(timeout=timeout).post(url, data=body, headers=headers, allow_redirects=False)
                if 200 <= resp.status_code < 300:
                    logger.info(
                        "Webhook delivered to %s (attempt %d/%d, status %d)",
                        redact(url),
                        attempt,
                        attempts,
                        resp.status_code,
                    )
                    return
                last_error = f"http_{resp.status_code}"
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            if attempt < attempts:
                time.sleep(0.25)
        logger.warning("Webhook delivery to %s failed after %d attempt(s): %s", redact(url), attempts, last_error)
    except Exception:
        # No redact() here: the import that provides it may be what failed.
        logger.exception("Webhook dispatch crashed unexpectedly")


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
            j = repo.get_job(job_id)
            if j:
                repo.update_job_progress(job_id, event.title, j.progress_done, j.progress_total)
        elif event.kind == "phase_done":
            j = repo.get_job(job_id)
            if j:
                repo.update_job_progress(job_id, event.title, j.progress_done + 1, j.progress_total)

    progress = CallbackProgress(callback=_on_event, total_phases=10)
    options = PipelineOptions(**{k: v for k, v in options_dict.items() if k in PipelineOptions.__dataclass_fields__})

    try:
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

        # --- LLM report: not yet supported headless (needs UI correlation context) ---
        if opts.get("llm_enabled", True):
            result.warnings.append(WARNING_LLM_UNSUPPORTED)

        _persist_analysis(result, job, pcap_path, osint_data, yara_results, repo)

        result_blob = json.dumps(result.to_dict()).encode("utf-8")
        repo.complete_job(job_id, result_blob)

        webhook_url = options_dict.get("webhook_url")
        if webhook_url:
            from app.api.settings import APISettings

            settings = APISettings.from_env()
            _dispatch_webhook(
                webhook_url,
                {
                    "job_id": job_id,
                    "case_id": job.case_id,
                    "status": "done",
                    "analysis_id": result.analysis_id or None,
                },
                timeout=settings.webhook_timeout_seconds,
                max_retries=settings.webhook_max_retries,
            )
    except Exception as exc:
        logger.exception("Job %s failed: %s", job_id, exc)
        repo.update_job_status(
            job_id,
            JS.FAILED,
            error_code="pipeline_error",
            error_detail=str(exc)[:500],
        )

        webhook_url = options_dict.get("webhook_url")
        if webhook_url:
            from app.api.settings import APISettings

            settings = APISettings.from_env()
            _dispatch_webhook(
                webhook_url,
                {
                    "job_id": job_id,
                    "case_id": job.case_id,
                    "status": "failed",
                    "analysis_id": None,
                },
                timeout=settings.webhook_timeout_seconds,
                max_retries=settings.webhook_max_retries,
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
