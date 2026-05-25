# tests/test_job_model.py
"""Tests for Job and JobStatus models."""

from __future__ import annotations

from datetime import datetime

from app.database.models import Job, JobStatus


def test_job_status_enum():
    assert JobStatus.from_str("queued") == JobStatus.QUEUED
    assert JobStatus.from_str("DONE") == JobStatus.DONE
    assert JobStatus.from_str("running") == JobStatus.RUNNING
    assert JobStatus.from_str("failed") == JobStatus.FAILED
    assert JobStatus.from_str("cancelled") == JobStatus.CANCELLED
    assert JobStatus.from_str("garbage") == JobStatus.QUEUED  # default


def test_job_round_trip():
    job = Job(
        id="j_abcd1234",
        case_id="abcd1234",
        pcap_path="/tmp/x.pcap",
        status=JobStatus.RUNNING,
        progress_stage="zeek",
        progress_done=4,
        progress_total=10,
        submitted_at=datetime(2026, 4, 27, 15, 30),
    )
    d = job.to_dict()
    assert d["status"] == "running"
    assert d["progress_done"] == 4
    assert d["progress_stage"] == "zeek"
    restored = Job.from_dict(d)
    assert restored.id == job.id
    assert restored.status == JobStatus.RUNNING
    assert restored.progress_stage == "zeek"


def test_job_defaults():
    job = Job(id="j_test", case_id="c1", pcap_path="/tmp/a.pcap")
    assert job.status == JobStatus.QUEUED
    assert job.progress_done == 0
    assert job.progress_total == 10
    assert job.error_code is None
    assert job.result_json is None


def test_job_to_dict_excludes_result_json():
    """result_json is a potentially large blob — not included in the summary dict."""
    job = Job(id="j_test", case_id="c1", pcap_path="/p.pcap", result_json='{"big": "blob"}')
    d = job.to_dict()
    assert "result_json" not in d
