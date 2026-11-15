"""API-side broker for the isolated offline worker; no Docker socket needed."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from app.agents.provenance import selected_options
from app.agents.registry import canonical, ensure_once
from app.database.models import Analysis, JobStatus

logger = logging.getLogger(__name__)

JOB_ID = re.compile(r"j_[a-f0-9]{16}")
ACTIVE = frozenset({JobStatus.QUEUED, JobStatus.RUNNING})
# Written by the trusted launcher into the results spool after every successful
# Docker ping. Parsers have no mount of that directory, so its timestamp is trusted.
LAUNCHER_HEARTBEAT = "launcher.heartbeat"
DEFAULT_WALL_SECONDS = 600
# How long a job may sit with no sign of a working launcher, on top of its wall budget.
QUEUE_WAIT_ALLOWANCE_SECONDS = 300
# Backstop for a launcher that looks alive but never reaches the job.
MAX_ACTIVE_SECONDS = 24 * 3600
# A launcher acknowledges a cancelled job it never started within one poll; after
# this grace the broker removes the never-dispatched input itself.
UNDISPATCHED_GRACE_SECONDS = 30
DEADLINE_EXCEEDED = "agent_job_deadline_exceeded"
# Reported by the launcher when Docker repeatedly refuses to create or start a job.
LAUNCHER_FAILED = "agent_launcher_failed"
CANCELLED_ABORT = "agent_job_cancelled"
# A deadline must be seen expired on passes this far apart before the job is failed.
# After a host suspend every timestamp looks stale for an instant; a live launcher
# refreshes its heartbeat within a second and clears the observation.
DEADLINE_CONFIRM_SECONDS = 10
# Selects jobs the agent broker owns. ``options_json LIKE '%_agent_id%'`` also matched any
# workbench job whose options merely contained that text (an upload named
# ``useragent_ids.pcap``), so the key itself is tested, and a row whose options are not
# valid JSON is treated as a non-agent job. Callers re-check the parsed option as well.
AGENT_JOB_SQL = "CASE WHEN json_valid(options_json) THEN json_extract(options_json, '$._agent_id') END IS NOT NULL"
_overdue: dict[tuple[str, str], float] = {}  # (database, job id) -> first pass that saw it overdue
MAX_PARSER_ASSERTED_BYTES = 16 * 1024
_PARSER_ASSERTED_KEYS = (
    "schema_version",
    "completed_at",
    "input_bytes",
    "options",
    "tool_versions",
    "rules_sha256",
    "rules_coverage",
)


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


def discard_input(job_id):
    """Retire one job's disposable input directory, then delete it.

    The rename is atomic, so the launcher sees either the complete directory
    (including any ``cancel.json``) or nothing at all. Neither step follows a
    link: ``os.rename`` moves a link itself and ``shutil.rmtree`` refuses one.

    Args:
        job_id: Agent job whose input copy is no longer needed. The original
            capture in application data is never touched.
    """
    if not JOB_ID.fullmatch(job_id):
        return
    root = input_root()
    retired = root / (".discard-" + job_id + "-" + uuid.uuid4().hex)
    try:
        os.rename(root / job_id, retired)
    except FileNotFoundError:
        return
    except OSError:
        logger.warning("Unable to retire agent job input %s", job_id, exc_info=True)
        return
    shutil.rmtree(retired, ignore_errors=True)


def request_stop(job_id, create=False):
    """Ask the launcher to stop (or never start) a job the broker has closed.

    Args:
        job_id: Closed agent job.
        create: Create the input directory when it does not exist yet, so a
            dispatch racing with the cancellation still finds the signal.
    """
    folder = input_root() / job_id
    if not JOB_ID.fullmatch(job_id):
        return
    try:
        if create:
            folder.mkdir(parents=True, exist_ok=True)
        if folder.is_dir() and not folder.is_symlink():
            atomic_json(folder / "cancel.json", {"cancelled": True})
    except OSError:
        if create:
            raise
        logger.warning("Unable to signal the launcher to stop job %s", job_id, exc_info=True)


def fail_active(repo, job_id, reason):
    """Fail a job only while it is still active; a concurrent cancellation stays terminal.

    Failing the job is what releases its queue-depth slot. Daily submission
    quota is counted per accepted submission and is not refunded on any failure.

    Returns:
        True when this call moved the job to ``failed``.
    """
    with closing(repo._get_conn()) as conn:
        changed = conn.execute(
            "UPDATE jobs SET status='failed',finished_at=?,error_code=? WHERE id=? AND status IN ('queued','running')",
            (datetime.now().isoformat(), reason, job_id),
        ).rowcount
        conn.commit()
    return changed > 0


def job_options(job):
    """Options the broker itself persisted at submission (trusted)."""
    try:
        options = json.loads(job.options_json or "{}")
    except (TypeError, ValueError):
        return {}
    return options if isinstance(options, dict) else {}


def wall_budget(options):
    """Seconds one parser run may take, from the broker-written job options."""
    value = options.get("_max_wall_seconds")
    if isinstance(value, bool) or not isinstance(value, int):
        return DEFAULT_WALL_SECONDS
    return max(1, min(value, MAX_ACTIVE_SECONDS))


def _epoch(value):
    """Seconds since the epoch; naive values are local time, as job rows are written."""
    return value.timestamp() if isinstance(value, datetime) else None


def _mtime(path, directory=False):
    """Modification time of a regular file (or directory) without following links."""
    try:
        metadata = os.lstat(path)
    except OSError:
        return None
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    return metadata.st_mtime if expected(metadata.st_mode) else None


def _latest(now, *moments):
    """Most recent known moment, never later than ``now``."""
    return max((min(moment, now) for moment in moments if moment is not None), default=None)


def launcher_last_seen(results):
    """Latest trusted sign that the launcher is working: its own or any job's heartbeat."""
    seen = [_mtime(results / LAUNCHER_HEARTBEAT)]
    try:
        seen.extend(_mtime(path) for path in results.glob("j_*.heartbeat"))
    except OSError:
        pass
    return max((moment for moment in seen if moment is not None), default=None)


def deadline_passed(job, options, launcher_seen, now):
    """Whether an active agent job has outlived its broker-side deadline.

    The deadline is the job's wall budget plus a queue-wait allowance, measured
    from the latest of its submission, its own launcher heartbeat and any other
    launcher activity. A healthy launcher that is busy with other jobs therefore
    never trips it; an absent, stopped or Docker-less launcher does.
    """
    submitted = _epoch(job.submitted_at)
    latest = _latest(now, submitted, _epoch(job.heartbeat_at), launcher_seen)
    if latest is None:
        return False
    if now - latest > wall_budget(options) + QUEUE_WAIT_ALLOWANCE_SECONDS:
        return True
    return submitted is not None and now - submitted > MAX_ACTIVE_SECONDS


def reap_inputs(repo, now):
    """Remove disposable inputs of closed agent jobs that no launcher will read again.

    An input is removed once the launcher has acknowledged the job with an
    output file. Without an acknowledgement it is removed after a short grace
    when the launcher never started the job (a cancellation or deadline before
    dispatch), and otherwise only after the job's full deadline has passed in
    silence, because a parser container may still be attached to it.
    """
    root, results = input_root(), output_root()
    try:
        folders = sorted(root.iterdir())
    except OSError:
        return
    for folder in folders:
        name = folder.name
        if name.startswith(".discard-"):
            shutil.rmtree(folder, ignore_errors=True)  # Interrupted removal; refuses links.
            continue
        if not JOB_ID.fullmatch(name):
            continue
        job = repo.get_job(name)
        if job is None or job.status in ACTIVE:
            continue
        options = job_options(job)
        if not options.get("_agent_id"):
            continue
        if not os.path.lexists(results / (name + ".json")):
            heartbeat = _mtime(results / (name + ".heartbeat"))
            dispatched = job.started_at is not None or heartbeat is not None
            quiet_since = _latest(now, _epoch(job.finished_at), heartbeat, _mtime(folder, directory=True))
            limit = wall_budget(options) + QUEUE_WAIT_ALLOWANCE_SECONDS if dispatched else UNDISPATCHED_GRACE_SECONDS
            if quiet_since is None or now - quiet_since <= limit:
                continue
        discard_input(name)


def _backfill_cancelled(repo):
    """Give legacy agent cancellations a ``finished_at`` so job retention can reap them."""
    with closing(repo._get_conn()) as conn:
        conn.execute(
            "UPDATE jobs SET finished_at=COALESCE(heartbeat_at,started_at,submitted_at,?) "
            "WHERE status='cancelled' AND finished_at IS NULL AND " + AGENT_JOB_SQL,
            (datetime.now().isoformat(),),
        )
        conn.commit()


def completion_time(repo, analysis_id, case_id):
    """Broker clock for a finished analysis; never a parser-supplied timestamp.

    Collection can be replayed after an interruption. Reusing the stamp already
    stored for this analysis keeps the replayed snapshot identical, and capping
    it at the current time repairs a stamp an older build took from the parser.
    """
    now = datetime.now(timezone.utc)
    with closing(repo._get_conn()) as conn:
        row = conn.execute(
            "SELECT analyzed_at FROM analyses WHERE id=? AND case_id=?", (analysis_id, case_id)
        ).fetchone()
    if row and row[0]:
        try:
            stored = datetime.fromisoformat(str(row[0]))
        except ValueError:
            return now
        if stored.tzinfo is None:
            stored = stored.replace(tzinfo=timezone.utc)
        return min(stored.astimezone(timezone.utc), now)
    return now


def parser_asserted(reported):
    """Bounded copy of what the untrusted parser said about itself."""
    kept = {key: reported[key] for key in _PARSER_ASSERTED_KEYS if key in reported}
    if len(canonical(kept).encode()) > MAX_PARSER_ASSERTED_BYTES:
        return {"omitted": "oversized"}
    return kept


def broker_provenance(job, options, isolation, reported, completed_at):
    """Ingest receipt built from broker-held facts.

    Everything at the top level comes from the broker or the trusted launcher.
    Tool versions, rule hashes and timestamps reported by the parser are
    unverifiable, so they are kept only under ``parser_asserted``.
    """
    return {
        "schema_version": "2",
        "run_id": job.id,
        "attempt_id": job.id,
        "input_bytes": os.path.getsize(job.pcap_path),
        "options": selected_options(options),
        "completed_at": completed_at.isoformat(),
        "isolation": isolation,
        "parser_asserted": parser_asserted(reported),
    }


def collect(repo, now=None):
    """Run one broker pass: enforce deadlines, relay launcher progress, persist results.

    Args:
        repo: Case repository for the shared database.
        now: Current time in epoch seconds; injectable for tests.
    """
    from app.api.queue import _sha256_file

    now = time.time() if now is None else now
    results = output_root()
    results.mkdir(parents=True, exist_ok=True)
    ensure_once(repo, "agent_cancel_backfill", lambda: _backfill_cancelled(repo))
    with closing(repo._get_conn()) as conn:
        pending = conn.execute(
            "SELECT id FROM jobs WHERE status IN ('queued','running') AND " + AGENT_JOB_SQL
        ).fetchall()
    launcher_seen = launcher_last_seen(results)
    database = str(repo._db_path)
    active = {(database, row["id"]) for row in pending}
    for observed in [key for key in _overdue if key[0] == database and key not in active]:
        del _overdue[observed]
    for row in pending:
        job = repo.get_job(row["id"])
        if not job or job.status not in ACTIVE:
            continue
        options = job_options(job)
        if not options.get("_agent_id"):
            continue  # Not an agent job: the workbench queue owns it.
        # A published output is the launcher's answer; never time out a job that has one.
        observed = (database, job.id)
        if not os.path.lexists(results / (job.id + ".json")) and deadline_passed(job, options, launcher_seen, now):
            if now - _overdue.setdefault(observed, now) >= DEADLINE_CONFIRM_SECONDS:
                _overdue.pop(observed, None)
                if fail_active(repo, job.id, DEADLINE_EXCEEDED):
                    logger.warning("Agent job %s exceeded its deadline without launcher progress", job.id)
                    request_stop(job.id)
                continue
        else:
            _overdue.pop(observed, None)
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
        if not job or job.status not in ACTIVE:
            continue  # reap_inputs() removes the input of a closed, acknowledged job.
        opts = job_options(job)
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
                # Parser bytes are only ever published beside an isolation receipt, so a
                # failure without one was written by the launcher itself.
                from_launcher = not os.path.lexists(results / (job_id + ".isolation"))
                if not (
                    reason in {"agent_time_budget_exceeded", "cancelled"}
                    or (reason == LAUNCHER_FAILED and from_launcher)
                ):
                    reason = "offline_worker_failed"
                fail_active(repo, job_id, reason)
                discard_input(job_id)
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
            reported = payload.get("provenance") or {}
            if not isinstance(reported, dict):
                raise ValueError("invalid provenance")
            analysis_id = job.id + "_analysis"
            completed_at = completion_time(repo, analysis_id, job.case_id)
            analysis = Analysis(
                id=analysis_id,
                case_id=job.case_id,
                analyzed_at=completed_at,
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
                    "evidence_provenance": broker_provenance(job, opts, isolation, reported, completed_at),
                },
            )
            analysis.iocs = repo.extract_iocs(analysis)
            try:
                data["analysis_id"] = repo.save_analysis(analysis)
            except sqlite3.IntegrityError as error:
                if CANCELLED_ABORT not in str(error):
                    raise
                # The cancellation committed first; the database refused the analysis.
                logger.info("Agent job %s was cancelled before its result was saved", job_id)
                continue
            repo.complete_job(
                job_id,
                canonical(
                    {"analysis_id": analysis.id, "case_id": job.case_id, "offline": True, "evidence_saved": True}
                ).encode(),
                only_active=True,
            )
            # This is only the disposable worker copy. The original capture remains in app data.
            discard_input(job_id)
        except (ValueError, TypeError, KeyError, OSError, RecursionError, AttributeError):
            fail_active(repo, job_id, "worker_result_invalid")
            discard_input(job_id)
    reap_inputs(repo, now)


async def broker_loop(repo):
    from app.utils.logger import get_logger

    get_logger(__name__)  # Attach the application's handlers to this module's logger.
    while True:
        try:
            await asyncio.to_thread(collect, repo)
        except Exception:
            logger.exception("Agent result collection failed")
        await asyncio.sleep(2)
