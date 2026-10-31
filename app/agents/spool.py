"""API-side broker for the isolated offline worker; no Docker socket needed."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import stat
import time
import uuid
from datetime import datetime
from pathlib import Path

from app.agents.registry import canonical
from app.database.models import Analysis, JobStatus


def spool_root():
    return Path(os.getenv("PCAP_HUNTER_AGENT_SPOOL", "data/agent-spool"))


def input_root():
    return Path(os.getenv("PCAP_HUNTER_AGENT_INPUT") or spool_root() / "inbox")


def output_root():
    return Path(os.getenv("PCAP_HUNTER_AGENT_OUTPUT") or spool_root() / "results")


def bounded_json(raw):
    """Bound structural allocation before decoding parser-controlled JSON."""
    quoted, escaped, depth, nodes = False, False, 0, 0
    for character in raw:
        if quoted:
            if escaped:
                escaped = False
            elif character == 92:
                escaped = True
            elif character == 34:
                quoted = False
        elif character == 34:
            quoted = True
        elif character in (91, 123):
            depth += 1
            nodes += 1
            if depth > 64:
                raise ValueError("Worker output nesting limit")
        elif character in (93, 125):
            depth -= 1
        elif character == 44:
            nodes += 1
        if nodes > 1_000_000:
            raise ValueError("Worker output complexity limit")

    def reject_constant(_value):
        raise ValueError("Non-finite worker output")

    value = json.loads(raw, parse_constant=reject_constant)
    # Reject invalid Unicode before it reaches persistence or evidence serialization.
    json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    return value


def read_output(name, maximum):
    """Open a bounded regular output without following worker-controlled links."""
    directory = os.open(output_root(), os.O_RDONLY | os.O_DIRECTORY)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("invalid worker output")
        raw = source.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("worker output too large")
        return bounded_json(raw)


def atomic_json(path, payload):
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    try:
        temporary.write_text(canonical(payload))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def dispatch(job):
    inbox = input_root() / job.id
    inbox.mkdir(parents=True, exist_ok=True)
    if not (inbox / "request.json").exists():
        source = Path(job.pcap_path)
        destination = inbox / "capture.pcap"
        temporary = inbox / (".capture-" + uuid.uuid4().hex)
        shutil.copyfile(source, temporary)
        os.replace(temporary, destination)
        atomic_json(inbox / "request.json", {"job_id": job.id, "case_id": job.case_id})


def fail_active(repo, job_id, reason):
    # A concurrent cancellation must remain terminal.
    with repo._get_conn() as conn:
        conn.execute(
            "UPDATE jobs SET status='failed',finished_at=?,error_code=? WHERE id=? AND status IN ('queued','running')",
            (datetime.now().isoformat(), reason, job_id),
        )
        conn.commit()


def collect(repo):
    from app.api.queue import _sha256_file

    results = output_root()
    results.mkdir(parents=True, exist_ok=True)
    with repo._get_conn() as conn:
        pending = conn.execute(
            "SELECT id FROM jobs WHERE status IN ('queued','running') AND options_json LIKE '%_agent_id%'"
        ).fetchall()
    for row in pending:
        job = repo.get_job(row["id"])
        if not job or job.status not in {JobStatus.QUEUED, JobStatus.RUNNING}:
            continue
        try:
            dispatch(job)
        except OSError:
            fail_active(repo, job.id, "worker_input_unavailable")
            continue
        heartbeat = results / (job.id + ".heartbeat")
        if heartbeat.is_file() and not heartbeat.is_symlink() and time.time() - heartbeat.stat().st_mtime < 15:
            try:
                current = read_output(job.id + ".heartbeat", 4096)
                if abs(time.time() - float(current["heartbeat"])) > 15:
                    continue
            except (ValueError, TypeError, KeyError, OSError):
                continue
            if job.status == JobStatus.QUEUED:
                repo.start_job_if_queued(job.id)
            repo.touch_job_heartbeat(job.id)
            repo.update_job_stage(job.id, "Offline packet analysis", 25, "Running in a private job container")
    for output in results.glob("j_*.json"):
        job_id = output.stem
        job = repo.get_job(job_id)
        if not job or job.status not in {JobStatus.QUEUED, JobStatus.RUNNING}:
            if job and job.status == JobStatus.CANCELLED:
                # An output is an acknowledgement that this worker has stopped.
                shutil.rmtree(input_root() / job_id, ignore_errors=True)
            continue
        opts = json.loads(job.options_json or "{}")
        if not opts.get("_agent_id"):
            continue
        if output.is_symlink() or output.stat().st_size > 32 * 1024 * 1024:
            fail_active(repo, job_id, "worker_result_invalid")
            continue
        try:
            payload = read_output(output.name, 32 * 1024 * 1024)
            if not isinstance(payload, dict):
                raise ValueError("invalid worker result")
            expected_hash = _sha256_file(job.pcap_path)
            if payload.get("input_sha256") != expected_hash or not payload.get("ok"):
                reason = payload.get("error_code")
                reason = reason if reason in {"agent_time_budget_exceeded", "cancelled"} else "offline_worker_failed"
                fail_active(repo, job_id, reason)
                shutil.rmtree(input_root() / job_id, ignore_errors=True)
                continue
            data = payload["result"]
            if not isinstance(data, dict) or not isinstance(data.get("features"), dict):
                raise ValueError("invalid features")
            isolation = read_output(job_id + ".isolation", 4096)
            if (
                not isinstance(isolation, dict)
                or isolation.get("job_id") != job_id
                or isolation.get("backend") != "docker-per-job"
                or isolation.get("network") != "none"
                or isolation.get("input_scope") != "single-read-only-job"
                or isolation.get("scratch") != "private-tmpfs"
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", isolation.get("image_id", ""))
                or not re.fullmatch(r"[a-f0-9]{64}", isolation.get("container_id", ""))
            ):
                raise ValueError("Missing trusted job isolation receipt")
            provenance = payload.get("provenance") or {}
            if not isinstance(provenance, dict):
                raise ValueError("invalid provenance")
            provenance["isolation"] = isolation
            analysis = Analysis(
                id=job.id + "_analysis",
                case_id=job.case_id,
                analyzed_at=datetime.fromisoformat(provenance["completed_at"])
                if provenance.get("completed_at")
                else job.submitted_at,
                pcap_path=job.pcap_path,
                pcap_hash=expected_hash,
                packet_count=max(0, int(data.get("packet_count", 0))),
                features=data["features"],
                osint={},
                report="",
                dns_analysis=data.get("dns_analysis"),
                tls_analysis=data.get("tls_analysis"),
                yara_results=data.get("yara_results"),
                attack_mapping=data.get("attack_mapping"),
                capture_metrics=data.get("capture_metrics"),
                session_artifacts={
                    "pipeline_stages": data.get("stages_run", []),
                    "pipeline_warnings": data.get("warnings", []),
                    "beacon_records": data.get("beacon_df_records", []),
                    "evidence_provenance": provenance,
                },
            )
            analysis.iocs = repo.extract_iocs(analysis)
            data["analysis_id"] = repo.save_analysis(analysis)
            repo.complete_job(
                job_id,
                canonical(
                    {"analysis_id": analysis.id, "case_id": job.case_id, "offline": True, "evidence_saved": True}
                ).encode(),
                only_active=True,
            )
            # This is only the disposable worker copy. The original capture remains in app data.
            shutil.rmtree(input_root() / job_id, ignore_errors=True)
        except (ValueError, TypeError, KeyError, OSError, RecursionError, AttributeError):
            fail_active(repo, job_id, "worker_result_invalid")
            shutil.rmtree(input_root() / job_id, ignore_errors=True)


async def broker_loop(repo):
    from app.utils.logger import get_logger

    logger = get_logger(__name__)
    while True:
        try:
            await asyncio.to_thread(collect, repo)
        except Exception:
            logger.exception("Agent result collection failed")
        await asyncio.sleep(2)
