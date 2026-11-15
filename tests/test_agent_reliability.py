"""Broker deadlines, launcher failure handling, trusted provenance and cancellation bookkeeping."""

import hashlib
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from app.agents import spool
from app.agents.evidence import EvidenceService
from app.agents.registry import AgentRegistry
from app.agents.spool import atomic_json, collect, dispatch, request_stop
from app.agents.supervisor import (
    CleanupError,
    Docker,
    DockerError,
    DockerUnavailable,
    Supervisor,
    job_spec,
    run,
)
from app.database.models import Analysis, Case, Job, JobStatus
from app.database.repository import CaseRepository

JOB_A = "j_000000000000000a"
JOB_B = "j_000000000000000b"
IMAGE = "sha256:" + "a" * 64
PCAP = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
OPTIONS = {
    "_agent_id": "a_test",
    "_max_wall_seconds": 600,
    "osint_enabled": False,
    "llm_enabled": False,
    "do_yara": True,
    "pyshark_packet_limit": 200000,
}


class Engine:
    """Docker client fake at the same seam as tests/test_agent_supervisor.py."""

    def __init__(self, stop_after=50):
        self.events, self.containers = [], []
        self.result = b'{"ok":true}'
        self.create_errors, self.start_errors = {}, {}
        self.pings, self.stop_after, self.stopping = 0, stop_after, None

    def json(self, method, path, payload=None):
        if path.startswith("/images/"):
            return {"Id": IMAGE, "Architecture": "arm64", "Os": "linux"}
        if path.startswith("/volumes/"):
            return {"Labels": {"com.docker.compose.project": "test"}}
        if path == "/info":
            return {"SecurityOptions": ["name=seccomp,profile=builtin"]}
        if path.startswith("/containers/create"):
            job_id = payload["Cmd"][1]
            self.events.append(("create", job_id, payload))
            if self.create_errors.get(job_id):
                raise self.create_errors[job_id]
            return {"Id": job_id[2:] * 4}
        if path.startswith("/containers/json"):
            return self.containers
        return {"State": {"Running": True}}

    def request(self, method, path):
        self.events.append((method, path))
        if path == "/_ping":
            self.pings += 1
            if self.pings >= self.stop_after:
                self.stopping.set()
        if path.endswith("/start"):
            container = path.split("/")[2]
            for job_id, error in self.start_errors.items():
                if container == job_id[2:] * 4:
                    raise error
        return b"OK"

    def read_file(self, *args):
        return self.result

    def creates(self, job_id):
        return [event for event in self.events if event[0] == "create" and event[1] == job_id]


@pytest.fixture
def launcher(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAP_HUNTER_AGENT_SPOOL", str(tmp_path))
    monkeypatch.delenv("PCAP_HUNTER_AGENT_INPUT", raising=False)
    monkeypatch.delenv("PCAP_HUNTER_AGENT_OUTPUT", raising=False)
    for job_id in (JOB_A, JOB_B):
        folder = tmp_path / "inbox" / job_id
        folder.mkdir(parents=True)
        (folder / "request.json").write_text(json.dumps({"job_id": job_id, "case_id": "0123456789ab"}))
        (folder / "capture.pcap").write_bytes(b"P" * 24)
    (tmp_path / "results").mkdir()
    engine = Engine()
    supervisor = Supervisor(engine, "trusted-image", "input", "test", retry_delay=0)
    supervisor.poll = 0
    engine.stopping = supervisor.stopping
    return supervisor, engine, tmp_path / "results"


def test_create_failure_becomes_a_failed_job_and_the_next_job_still_runs(launcher):
    supervisor, engine, results = launcher
    engine.create_errors[JOB_A] = DockerError(500)
    engine.stop_after = 6
    supervisor.serve()
    # A trusted failure receipt written by the launcher, never parser bytes.
    assert json.loads((results / (JOB_A + ".json")).read_text()) == {
        "ok": False,
        "error_code": "agent_launcher_failed",
    }
    assert not (results / (JOB_A + ".isolation")).exists()
    assert len(engine.creates(JOB_A)) == 3  # bounded: no fourth attempt, no wedge
    assert (results / (JOB_B + ".json")).read_bytes() == engine.result
    assert json.loads((results / (JOB_B + ".isolation")).read_text())["job_id"] == JOB_B
    order = [event[1] for event in engine.events if event[0] == "create"]
    assert order.index(JOB_B) < len(order) - 1 - order[::-1].index(JOB_A)  # B ran before A was given up on
    # Every attempt used the unchanged, fully restricted container specification.
    assert all(event[2] == job_spec(JOB_A, IMAGE, "input", "test") for event in engine.creates(JOB_A))


def test_start_failure_removes_the_container_before_reporting(launcher):
    supervisor, engine, results = launcher
    engine.start_errors[JOB_A] = DockerError(500)
    engine.stop_after = 6
    supervisor.serve()
    assert json.loads((results / (JOB_A + ".json")).read_text())["error_code"] == "agent_launcher_failed"
    container = JOB_A[2:] * 4
    starts = [index for index, event in enumerate(engine.events) if event == ("POST", f"/containers/{container}/start")]
    assert len(starts) == 3
    for index in starts:
        assert engine.events[index + 1] == ("DELETE", f"/containers/{container}?force=1&v=0")
    assert (results / (JOB_B + ".json")).exists()


def test_failed_job_backs_off_instead_of_retrying_every_pass(launcher):
    supervisor, engine, results = launcher
    supervisor.retry_delay = 1000
    engine.create_errors[JOB_A] = DockerUnavailable("connection reset")
    engine.stop_after = 5
    supervisor.serve()
    assert len(engine.creates(JOB_A)) == 1
    assert not (results / (JOB_A + ".json")).exists()
    assert supervisor.failures[JOB_A][0] == 1
    assert (results / (JOB_B + ".json")).exists()
    # A retry first removes any container the failed create left behind, and only its own.
    labels = {"org.pcap-hunter.runner": "test", "org.pcap-hunter.agent-job": "1"}
    engine.containers = [
        {"Id": "c" * 64, "Labels": labels | {"org.pcap-hunter.job": JOB_A}, "Names": ["/ph-test-" + JOB_A]},
        {"Id": "d" * 64, "Labels": labels | {"org.pcap-hunter.job": JOB_B}, "Names": ["/ph-test-" + JOB_B]},
        {"Id": "e" * 64, "Labels": labels | {"org.pcap-hunter.job": JOB_A}, "Names": ["/unrelated"]},
    ]
    engine.events.clear()
    supervisor.failures[JOB_A] = (1, 0.0)
    engine.create_errors.clear()
    engine.pings, engine.stop_after = 0, 2
    supervisor.stopping.clear()
    supervisor.recover = lambda job_id=None, original=supervisor.recover: job_id and original(job_id)
    supervisor.serve()
    deletes = [event[1] for event in engine.events if event[0] == "DELETE"]
    assert deletes[0] == "/containers/" + "c" * 64 + "?force=1&v=0"
    assert not any("d" * 64 in path or "e" * 64 in path for path in deletes)
    assert (results / (JOB_A + ".json")).read_bytes() == engine.result and JOB_A not in supervisor.failures


def test_launcher_publishes_trusted_liveness_after_each_docker_ping(launcher):
    supervisor, engine, results = launcher
    engine.stop_after = 1
    supervisor.serve()
    assert abs(json.loads((results / "launcher.heartbeat").read_text())["heartbeat"] - time.time()) < 5


def test_unreachable_daemon_is_typed_and_backs_off_without_exiting(tmp_path):
    with pytest.raises(DockerUnavailable):
        Docker(str(tmp_path / "missing.sock")).request("GET", "/_ping")

    stopping, calls, waits = threading.Event(), [], []

    class Flaky:
        def serve(self):
            calls.append("serve")
            if calls.count("serve") == 1:
                raise DockerUnavailable("down")
            if calls.count("serve") == 2:
                raise CleanupError("parser may be alive")
            if calls.count("serve") == 3:
                raise DockerError(500)
            stopping.set()

    original = stopping.wait
    stopping.wait = lambda delay: (waits.append(delay), original(0))[1]

    def create():
        calls.append("create")
        if calls == ["create"]:
            raise DockerUnavailable("starting")
        return Flaky()

    run(create, stopping, first_delay=0.25, limit=1.0)
    # One supervisor is kept; serve() (which starts with container recovery) is re-entered.
    assert calls == ["create", "create", "serve", "serve", "serve", "serve"]
    assert waits == [0.25, 0.5, 1.0, 1.0]  # exponential and capped: never a hot spin


def test_configuration_and_programming_errors_still_stop_the_launcher():
    for error in (DockerError(404), ValueError("Input volume belongs to a different Compose project")):

        def create(error=error):
            raise error

        with pytest.raises(type(error)):
            run(create, threading.Event(), first_delay=0)

    class Broken:
        def serve(self):
            raise AttributeError("bug")

    with pytest.raises(AttributeError):
        run(Broken, threading.Event(), first_delay=0)


# ---------------------------------------------------------------- broker side


@pytest.fixture
def broker(tmp_path, monkeypatch):
    root = tmp_path / "spool"
    monkeypatch.setenv("PCAP_HUNTER_AGENT_SPOOL", str(root))
    monkeypatch.delenv("PCAP_HUNTER_AGENT_INPUT", raising=False)
    monkeypatch.delenv("PCAP_HUNTER_AGENT_OUTPUT", raising=False)
    repo = CaseRepository(str(tmp_path / "cases.db"))
    repo.create_case(Case(id="0123456789ab", title="Synthetic"))
    source = tmp_path / "capture.pcap"
    source.write_bytes(PCAP)
    job = Job(id=JOB_A, case_id="0123456789ab", pcap_path=str(source), options_json=json.dumps(OPTIONS))
    repo.create_job(job)
    dispatch(job)
    (root / "results").mkdir()
    return repo, root, source, job


def isolation(root, job_id):
    atomic_json(
        root / "results" / (job_id + ".isolation"),
        {
            "job_id": job_id,
            "backend": "docker-per-job",
            "image_id": IMAGE,
            "container_id": "b" * 64,
            "network": "none",
            "input_scope": "single-read-only-job",
            "scratch": "private-tmpfs",
        },
    )


def success(root, source, job_id, **extra):
    isolation(root, job_id)
    payload = {
        "ok": True,
        "input_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "result": {"packet_count": 1, "features": {"flows": [], "artifacts": {"ips": ["192.0.2.1"]}}},
    }
    atomic_json(root / "results" / (job_id + ".json"), payload | extra)


def count(repo, sql, *params):
    conn = repo._get_conn()
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


def test_job_without_a_launcher_fails_at_its_deadline_and_frees_the_queue(broker, monkeypatch):
    repo, root, _, job = broker
    monkeypatch.setattr(spool, "reap_inputs", lambda *args: None)
    now = time.time()
    collect(repo, now + 600 + 290)  # inside wall budget + queue-wait allowance
    assert repo.get_job(job.id).status == JobStatus.QUEUED
    assert count(repo, "SELECT count(*) FROM jobs WHERE status IN ('queued','running')") == 1
    collect(repo, now + 600 + 310)
    # One stale-looking pass (for example right after a host resume) is not enough.
    assert repo.get_job(job.id).status == JobStatus.QUEUED
    collect(repo, now + 600 + 310 + spool.DEADLINE_CONFIRM_SECONDS)
    failed = repo.get_job(job.id)
    assert failed.status == JobStatus.FAILED and failed.error_code == "agent_job_deadline_exceeded"
    assert failed.finished_at is not None  # reapable by job retention
    assert count(repo, "SELECT count(*) FROM jobs WHERE status IN ('queued','running')") == 0  # depth released
    # A launcher that appears later is told not to start the parser.
    assert json.loads((root / "inbox" / job.id / "cancel.json").read_text()) == {"cancelled": True}
    assert repo.get_case(job.case_id).analyses == []


def test_launcher_activity_extends_the_deadline_until_the_absolute_backstop(broker):
    repo, root, _, job = broker
    later = time.time() + 5000
    heartbeat = root / "results" / "launcher.heartbeat"
    atomic_json(heartbeat, {"heartbeat": later})
    os.utime(heartbeat, (later - 60, later - 60))
    collect(repo, later)  # the launcher is alive and busy with other jobs
    assert repo.get_job(job.id).status == JobStatus.QUEUED
    # Another job's fresh heartbeat is launcher activity too (older launcher builds).
    heartbeat.unlink()
    other = root / "results" / (JOB_B + ".heartbeat")
    atomic_json(other, {"heartbeat": later})
    os.utime(other, (later - 60, later - 60))
    collect(repo, later)
    assert repo.get_job(job.id).status == JobStatus.QUEUED
    # A link is never trusted as a liveness signal.
    other.unlink()
    target = root / "elsewhere"
    target.write_text("{}")
    os.utime(target, (later, later))
    heartbeat.symlink_to(target)
    assert spool.launcher_last_seen(root / "results") is None
    heartbeat.unlink()
    # Alive but never reaching the job: the absolute backstop still ends it.
    far = time.time() + spool.MAX_ACTIVE_SECONDS + 100
    atomic_json(heartbeat, {"heartbeat": far})
    os.utime(heartbeat, (far - 5, far - 5))
    collect(repo, far)
    collect(repo, far + spool.DEADLINE_CONFIRM_SECONDS)
    assert repo.get_job(job.id).error_code == "agent_job_deadline_exceeded"


def test_one_stale_observation_is_forgotten_when_the_launcher_reappears(broker):
    repo, root, _, job = broker
    resumed = time.time() + 7200  # every timestamp looks two hours old after a suspend
    collect(repo, resumed)
    heartbeat = root / "results" / "launcher.heartbeat"
    atomic_json(heartbeat, {"heartbeat": resumed})
    os.utime(heartbeat, (resumed + 1, resumed + 1))
    collect(repo, resumed + spool.DEADLINE_CONFIRM_SECONDS)
    assert repo.get_job(job.id).status == JobStatus.QUEUED and not spool._overdue


def test_published_result_is_collected_even_long_after_the_deadline(broker):
    repo, root, source, job = broker
    success(root, source, job.id)
    collect(repo, time.time() + 100000)
    assert repo.get_job(job.id).status == JobStatus.DONE


def test_launcher_failure_code_is_trusted_only_without_parser_output(broker):
    repo, root, source, job = broker
    atomic_json(root / "results" / (job.id + ".json"), {"ok": False, "error_code": "agent_launcher_failed"})
    collect(repo)
    failed = repo.get_job(job.id)
    assert failed.status == JobStatus.FAILED and failed.error_code == "agent_launcher_failed"
    assert not (root / "inbox" / job.id).exists() and source.is_file()


def test_parser_cannot_claim_a_launcher_failure(broker):
    repo, root, _, job = broker
    isolation(root, job.id)  # parser bytes are only ever published beside this receipt
    atomic_json(root / "results" / (job.id + ".json"), {"ok": False, "error_code": "agent_launcher_failed"})
    collect(repo)
    assert repo.get_job(job.id).error_code == "offline_worker_failed"


def test_forged_future_completed_at_cannot_become_the_latest_analysis(broker):
    repo, root, source, job = broker
    forged = {
        "completed_at": "2999-01-01T00:00:00+00:00",
        "options": {"pyshark_packet_limit": 1, "osint_enabled": True},
        "tool_versions": {"tshark": "forged"},
        "rules_sha256": "f" * 64,
        "input_bytes": 1,
        "isolation": {"network": "host"},
        "unexpected": "x" * 100,
    }
    success(root, source, job.id, provenance=forged)
    before = datetime.now(timezone.utc)
    collect(repo)
    result = json.loads(repo.get_job(job.id).result_json)
    analysis = repo.get_analysis(result["analysis_id"])
    assert analysis.analyzed_at.utcoffset() == timedelta(0)
    assert before - timedelta(seconds=5) <= analysis.analyzed_at <= datetime.now(timezone.utc)
    stored = count(repo, "SELECT analyzed_at FROM analyses WHERE id=?", analysis.id)
    assert stored.endswith("+00:00") and not stored.startswith("2999")
    receipt = analysis.session_artifacts["evidence_provenance"]
    assert receipt["completed_at"] == analysis.analyzed_at.isoformat()
    # Broker-held facts at the top level ...
    assert receipt["options"] == {key: value for key, value in OPTIONS.items() if key != "_agent_id"}
    assert receipt["input_bytes"] == len(PCAP) and receipt["isolation"]["network"] == "none"
    assert "tool_versions" not in receipt and "rules_sha256" not in receipt
    # ... and parser claims only under an explicit, bounded key.
    assert receipt["parser_asserted"] == {key: forged[key] for key in forged if key not in {"isolation", "unexpected"}}
    manifest = EvidenceService(repo).manifest(analysis)
    assert manifest["coverage"]["provenance"] == "ingest_receipt"
    assert manifest["coverage"]["parser_limit"] == 200000  # what the broker submitted, not the parser's 1
    assert manifest["analyzed_at"] == analysis.analyzed_at.isoformat()


def test_oversized_parser_claims_are_dropped_not_stored(broker):
    repo, root, source, job = broker
    success(root, source, job.id, provenance={"tool_versions": {"tshark": "v" * 20000}})
    collect(repo)
    analysis = repo.get_analysis(job.id + "_analysis")
    assert analysis.session_artifacts["evidence_provenance"]["parser_asserted"] == {"omitted": "oversized"}


def test_old_receipt_shape_remains_readable(broker):
    repo, _, source, job = broker
    legacy = {"schema_version": "1", "options": {"pyshark_packet_limit": 7}, "tool_versions": {"tshark": "4"}}
    analysis = Analysis(
        id="legacy", case_id=job.case_id, pcap_path=str(source), session_artifacts={"evidence_provenance": legacy}
    )
    repo.save_analysis(analysis)
    manifest = EvidenceService(repo).manifest(analysis)
    assert manifest["coverage"]["parser_limit"] == 7 and manifest["provenance"]["tool_versions"] == {"tshark": "4"}


def cancel_like_the_route(repo, job_id):
    with AgentRegistry(repo).connection(write=True) as conn:
        conn.execute(
            "UPDATE jobs SET status='cancelled',finished_at=? WHERE id=? AND status IN ('queued','running')",
            (datetime.now().isoformat(), job_id),
        )
    request_stop(job_id, create=True)


def test_cancel_landing_during_collection_never_persists_an_analysis(broker, monkeypatch):
    repo, root, source, job = broker
    success(root, source, job.id)
    original = repo.extract_iocs

    def cancel_then_extract(analysis):
        # collect() already read the job as active; the cancel commits just before persistence.
        cancel_like_the_route(repo, job.id)
        return original(analysis)

    monkeypatch.setattr(repo, "extract_iocs", cancel_then_extract)
    collect(repo)
    assert repo.get_job(job.id).status == JobStatus.CANCELLED
    assert count(repo, "SELECT count(*) FROM analyses") == 0
    assert count(repo, "SELECT count(*) FROM iocs") == 0
    assert count(repo, "SELECT count(*) FROM evidence_snapshots") == 0
    assert count(repo, "SELECT count(*) FROM evidence_records") == 0
    # The output is the launcher's acknowledgement, so the disposable input goes too.
    assert not (root / "inbox" / job.id).exists() and source.is_file()
    collect(repo)  # and nothing is revived on a later pass
    assert repo.get_job(job.id).status == JobStatus.CANCELLED and count(repo, "SELECT count(*) FROM analyses") == 0


def test_database_refuses_an_analysis_for_a_cancelled_agent_job_only(broker):
    repo, _, source, job = broker
    cancel_like_the_route(repo, job.id)
    with pytest.raises(sqlite3.IntegrityError, match="agent_job_cancelled"):
        repo.save_analysis(Analysis(id=job.id + "_analysis", case_id=job.case_id, pcap_path=str(source)))
    # Ordinary analyses, and ones for jobs that are not cancelled, are unaffected.
    assert repo.save_analysis(Analysis(id="plain", case_id=job.case_id, pcap_path=str(source))) == "plain"
    other = JOB_B + "_analysis"
    assert repo.save_analysis(Analysis(id=other, case_id=job.case_id, pcap_path=str(source))) == other
    assert repo.save_analysis(Analysis(id=other, case_id=job.case_id, pcap_path=str(source), packet_count=2)) == other
    # An analysis saved before its job was cancelled can still be re-saved by an analyst.
    repo.create_job(Job(id=JOB_B, case_id=job.case_id, pcap_path=str(source), options_json=json.dumps(OPTIONS)))
    cancel_like_the_route(repo, JOB_B)
    assert repo.save_analysis(Analysis(id=other, case_id=job.case_id, pcap_path=str(source), packet_count=3)) == other
    assert repo.get_analysis(other).packet_count == 3


def test_cancelled_job_that_was_never_dispatched_is_cleaned_after_a_grace(broker):
    repo, root, source, job = broker
    cancel_like_the_route(repo, job.id)
    assert repo.get_job(job.id).finished_at is not None
    folder = root / "inbox" / job.id
    collect(repo)  # a live launcher still gets a moment to acknowledge it
    assert (folder / "cancel.json").exists() and (folder / "capture.pcap").exists()
    stale = root / "inbox" / (".discard-" + JOB_B + "-leftover")
    stale.mkdir()
    (stale / "capture.pcap").write_bytes(PCAP)
    collect(repo, time.time() + spool.UNDISPATCHED_GRACE_SECONDS + 5)
    assert not folder.exists() and not stale.exists()
    assert list((root / "inbox").iterdir()) == []
    assert source.is_file()  # only the disposable copy is removed


def test_cancelled_job_a_launcher_started_waits_for_its_acknowledgement(broker):
    repo, root, _, job = broker
    heartbeat = root / "results" / (job.id + ".heartbeat")
    atomic_json(heartbeat, {"heartbeat": time.time()})
    collect(repo)
    assert repo.get_job(job.id).status == JobStatus.RUNNING
    cancel_like_the_route(repo, job.id)
    folder = root / "inbox" / job.id
    collect(repo, time.time() + spool.UNDISPATCHED_GRACE_SECONDS + 5)
    assert (folder / "cancel.json").exists()  # a parser may still be attached to this input
    atomic_json(root / "results" / (job.id + ".json"), {"ok": False, "error_code": "cancelled"})
    collect(repo)
    assert not folder.exists() and repo.get_job(job.id).status == JobStatus.CANCELLED


def test_input_removal_never_follows_a_link(broker, tmp_path):
    repo, root, _, job = broker
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "keep.txt").write_text("keep")
    cancel_like_the_route(repo, job.id)
    folder = root / "inbox" / job.id
    for child in folder.iterdir():
        child.unlink()
    folder.rmdir()
    folder.symlink_to(protected, target_is_directory=True)
    request_stop(job.id)  # must not write through the link
    collect(repo, time.time() + 100000)
    spool.discard_input(job.id)
    spool.discard_input("../protected")
    assert sorted(path.name for path in protected.iterdir()) == ["keep.txt"]


def test_legacy_cancellations_gain_a_finish_time_for_retention(broker):
    repo, _, _, job = broker
    conn = repo._get_conn()
    conn.execute("UPDATE jobs SET status='cancelled',finished_at=NULL WHERE id=?", (job.id,))
    conn.commit()
    conn.close()
    collect(repo)
    assert repo.get_job(job.id).finished_at is not None


def test_workbench_job_mentioning_agent_id_is_never_touched_by_the_broker(broker, tmp_path):
    repo, root, source, _ = broker
    # Production shape of a workbench submission: the upload name is stored as display_name.
    workbench = {"display_name": "useragent_ids.pcap", "osint_enabled": False, "note": "x_agent_id y"}
    queued = Job(id=JOB_B, case_id="0123456789ab", pcap_path=str(source), options_json=json.dumps(workbench))
    repo.create_job(queued)
    cancelled = Job(
        id="j_000000000000000c", case_id="0123456789ab", pcap_path=str(source), options_json=json.dumps(workbench)
    )
    repo.create_job(cancelled)
    broken = Job(id="j_000000000000000d", case_id="0123456789ab", pcap_path=str(source), options_json="{_agent_id")
    repo.create_job(broken)
    conn = repo._get_conn()
    conn.execute("UPDATE jobs SET status='cancelled',finished_at=NULL WHERE id=?", (cancelled.id,))
    conn.commit()
    conn.close()
    # A stray folder that looks like an agent input must not be reaped for a workbench job.
    stray = root / "inbox" / cancelled.id
    stray.mkdir()
    (stray / "capture.pcap").write_bytes(PCAP)

    far = time.time() + spool.MAX_ACTIVE_SECONDS + 100
    collect(repo, far)
    collect(repo, far + spool.DEADLINE_CONFIRM_SECONDS)

    assert repo.get_job(JOB_A).error_code == "agent_job_deadline_exceeded"  # the real agent job still is
    for job_id in (queued.id, broken.id):
        untouched = repo.get_job(job_id)
        assert untouched.status == JobStatus.QUEUED and untouched.error_code is None
        assert not (root / "inbox" / job_id).exists()  # the capture was never copied to the parser inbox
    assert repo.get_job(cancelled.id).finished_at is None  # the legacy backfill is for agent jobs only
    assert (stray / "capture.pcap").exists()


def test_transport_failure_after_the_parser_started_fails_the_job_once(launcher):
    supervisor, engine, results = launcher
    container = JOB_A[2:] * 4
    original = engine.read_file

    def starved(target, *args):
        if target == container:
            raise DockerUnavailable("timed out")  # a parser starving the exec call
        return original(target, *args)

    engine.read_file = starved
    engine.stop_after = 6
    supervisor.serve()
    assert len(engine.creates(JOB_A)) == 1  # no second and third full run for a started parser
    assert json.loads((results / (JOB_A + ".json")).read_text()) == {
        "ok": False,
        "error_code": "agent_launcher_failed",
    }
    assert not (results / (JOB_A + ".isolation")).exists()  # trusted: written without parser output
    start = engine.events.index(("POST", f"/containers/{container}/start"))
    assert ("DELETE", f"/containers/{container}?force=1&v=0") in engine.events[start:]
    assert JOB_A not in supervisor.failures
    assert (results / (JOB_B + ".json")).read_bytes() == engine.result


def test_inspect_failure_after_start_is_not_retried_either(launcher):
    supervisor, engine, results = launcher
    original = engine.json

    def inspect_fails(method, path, payload=None):
        if path == f"/containers/{JOB_A[2:] * 4}/json":
            raise DockerUnavailable("connection reset")
        return original(method, path, payload)

    engine.json = inspect_fails
    engine.stop_after = 6
    supervisor.serve()
    assert len(engine.creates(JOB_A)) == 1
    assert json.loads((results / (JOB_A + ".json")).read_text())["error_code"] == "agent_launcher_failed"


def test_cleanup_failure_after_a_started_job_still_publishes_nothing(launcher):
    supervisor, engine, results = launcher
    container = JOB_A[2:] * 4
    engine.read_file = lambda *args: (_ for _ in ()).throw(DockerUnavailable("timed out"))
    original = engine.request

    def request(method, path):
        if method == "DELETE" and container in path:
            raise DockerUnavailable("timed out")
        return original(method, path)

    engine.request = request
    with pytest.raises(CleanupError):
        supervisor.serve()
    assert not (results / (JOB_A + ".json")).exists()  # a parser that may be alive is never acknowledged
