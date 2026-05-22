# tests/api/test_models.py
"""Tests for Pydantic API models."""

from __future__ import annotations

from app.api.models import (
    JobStatusResponse,
    PcapSubmissionForm,
    ProblemDetail,
)


def test_pcap_submission_form_parses():
    form = PcapSubmissionForm(name="t", tags='["soar:tines"]', severity_hint="high")
    parsed = form.parsed_tags()
    assert parsed == ["soar:tines"]


def test_pcap_submission_form_empty_tags():
    form = PcapSubmissionForm()
    assert form.parsed_tags() == []


def test_pcap_submission_form_csv_tags():
    form = PcapSubmissionForm(tags="tag1, tag2, tag3")
    assert form.parsed_tags() == ["tag1", "tag2", "tag3"]


def test_problem_detail_serialization():
    p = ProblemDetail(
        type="https://x/errors/foo",
        title="t",
        status=400,
        detail="d",
        instance="/api/v1/x",
        code="foo",
    )
    d = p.model_dump()
    assert d["status"] == 400
    assert d["code"] == "foo"


def test_job_status_response_round_trip():
    from app.api.models import JobProgress

    r = JobStatusResponse(
        job_id="j_abc",
        case_id="abc",
        status="running",
        progress=JobProgress(stage="zeek", stages_done=3, stages_total=10, percent=30),
        submitted_at="2026-04-27T15:30:00",
        started_at="2026-04-27T15:30:01",
        finished_at=None,
        error=None,
    )
    d = r.model_dump()
    assert d["progress"]["stage"] == "zeek"
    assert d["error"] is None
