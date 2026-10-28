"""Native worker output must pass through a checked persistence broker."""

import hashlib
import json
import time

from app.agents.spool import atomic_json, collect, dispatch
from app.database.models import Case, Job, JobStatus
from app.database.repository import CaseRepository


def setup_job(tmp_path, monkeypatch):
    root = tmp_path / "spool"
    monkeypatch.setenv("PCAP_HUNTER_AGENT_SPOOL", str(root))
    repo = CaseRepository(str(tmp_path / "cases.db"))
    repo.create_case(Case(id="0123456789ab", title="Synthetic"))
    source = tmp_path / "capture.pcap"
    source.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
    job = Job(
        id="j_0123456789abcdef",
        case_id="0123456789ab",
        pcap_path=str(source),
        options_json=json.dumps({"_agent_id": "a_test", "osint_enabled": False, "llm_enabled": False}),
    )
    repo.create_job(job)
    dispatch(job)
    (root / "results").mkdir()
    atomic_json(
        root / "results" / (job.id + ".isolation"),
        {
            "job_id": job.id,
            "backend": "docker-per-job",
            "image_id": "sha256:" + "a" * 64,
            "container_id": "b" * 64,
            "network": "none",
            "input_scope": "single-read-only-job",
            "scratch": "private-tmpfs",
        },
    )
    return repo, root, source, job


def test_broker_saves_evidence_before_completing_job(tmp_path, monkeypatch):
    repo, root, source, job = setup_job(tmp_path, monkeypatch)
    atomic_json(
        root / "results" / (job.id + ".json"),
        {
            "ok": True,
            "input_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "result": {
                "packet_count": 1,
                "features": {"flows": [], "artifacts": {"ips": ["192.0.2.1"]}},
                "stages_run": ["pre_count"],
            },
        },
    )
    collect(repo)
    saved = repo.get_job(job.id)
    assert saved.status == JobStatus.DONE
    result = json.loads(saved.result_json)
    assert result["evidence_saved"] is True
    assert repo.get_analysis(result["analysis_id"]).case_id == job.case_id
    assert source.is_file()


def test_trusted_heartbeat_starts_queued_job_without_losing_completion(tmp_path, monkeypatch):
    repo, root, source, job = setup_job(tmp_path, monkeypatch)
    atomic_json(root / "results" / (job.id + ".heartbeat"), {"heartbeat": time.time()})
    collect(repo)
    assert repo.get_job(job.id).status == JobStatus.RUNNING
    successful_output(root, source, job)
    collect(repo)
    assert repo.get_job(job.id).status == JobStatus.DONE


def test_broker_rejects_results_for_a_different_capture(tmp_path, monkeypatch):
    repo, root, _, job = setup_job(tmp_path, monkeypatch)
    atomic_json(
        root / "results" / (job.id + ".json"), {"ok": True, "input_sha256": "0" * 64, "result": {"features": {}}}
    )
    collect(repo)
    assert repo.get_job(job.id).status == JobStatus.FAILED
    assert repo.get_case(job.case_id).analyses == []


def test_spool_dispatch_is_retryable_without_rewriting_the_capture(tmp_path, monkeypatch):
    repo, root, source, job = setup_job(tmp_path, monkeypatch)
    path = root / "inbox" / job.id / "capture.pcap"
    before = path.stat().st_mtime_ns
    dispatch(job)
    assert path.stat().st_mtime_ns == before
    assert path.read_bytes() == source.read_bytes()


def test_worker_outputs_cannot_follow_links_or_block_on_special_files(tmp_path, monkeypatch):
    import os

    import pytest

    from app.agents.spool import read_output

    _, root, _, _ = setup_job(tmp_path, monkeypatch)
    protected = tmp_path / "protected.json"
    protected.write_text('{"secret":"inert-test-value"}')
    (root / "results" / "link.json").symlink_to(protected)
    with pytest.raises(OSError):
        read_output("link.json", 100)
    if hasattr(os, "mkfifo"):
        os.mkfifo(root / "results" / "pipe.json")
        with pytest.raises(ValueError, match="invalid worker output"):
            read_output("pipe.json", 100)
    assert protected.read_text() == '{"secret":"inert-test-value"}'


def successful_output(root, source, job):
    atomic_json(
        root / "results" / (job.id + ".json"),
        {
            "ok": True,
            "input_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "result": {"features": {"flows": []}},
        },
    )


def test_collection_recovery_reuses_analysis_and_snapshot(tmp_path, monkeypatch):
    import pytest

    repo, root, source, job = setup_job(tmp_path, monkeypatch)
    successful_output(root, source, job)
    original = repo.complete_job
    monkeypatch.setattr(repo, "complete_job", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("restart")))
    with pytest.raises(RuntimeError, match="restart"):
        collect(repo)
    monkeypatch.setattr(repo, "complete_job", original)
    collect(repo)
    with repo._get_conn() as conn:
        assert conn.execute("SELECT count(*) FROM analyses").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM evidence_snapshots").fetchone()[0] == 1
    assert repo.get_job(job.id).status == JobStatus.DONE


def test_finishing_worker_does_not_revive_concurrent_cancellation(tmp_path, monkeypatch):
    repo, root, source, job = setup_job(tmp_path, monkeypatch)
    successful_output(root, source, job)
    original = repo.save_analysis

    def save_then_cancel(analysis):
        result = original(analysis)
        repo.update_job_status(job.id, JobStatus.CANCELLED)
        return result

    monkeypatch.setattr(repo, "save_analysis", save_then_cancel)
    collect(repo)
    assert repo.get_job(job.id).status == JobStatus.CANCELLED
    assert source.is_file()


def test_malformed_worker_result_and_missing_input_are_terminal(tmp_path, monkeypatch):
    repo, root, source, job = setup_job(tmp_path, monkeypatch)
    atomic_json(root / "results" / (job.id + ".json"), ["invalid"])
    collect(repo)
    assert repo.get_job(job.id).error_code == "worker_result_invalid"
    assert source.is_file()


def test_successful_result_requires_a_separate_trusted_isolation_receipt(tmp_path, monkeypatch):
    repo, root, source, job = setup_job(tmp_path, monkeypatch)
    successful_output(root, source, job)
    (root / "results" / (job.id + ".isolation")).unlink()
    collect(repo)
    assert repo.get_job(job.id).error_code == "worker_result_invalid"
    assert repo.get_case(job.case_id).analyses == []
    assert source.is_file()
