"""Durable Streamlit background-job submission, recovery, and restore tests."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from app.database.models import Analysis, Case, Job, JobStatus
from app.database.repository import CaseRepository
from app.ui import background_analysis as bg


class _RecordingQueue:
    def __init__(self, repo: CaseRepository):
        self.repo = repo
        self.submissions = []

    def enqueue(self, submission):
        self.submissions.append(submission)
        return self.repo.create_job(
            Job(
                case_id=submission.case_id,
                pcap_path=submission.pcap_path,
                options_json=json.dumps(submission.options),
            )
        )


def test_submit_creates_autosaved_case_and_durable_jobs(tmp_path, monkeypatch):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    queue = _RecordingQueue(repo)
    monkeypatch.setattr(bg, "get_background_repo", lambda: repo)
    monkeypatch.setattr(bg, "get_background_queue", lambda: queue)

    run = bg.submit_background_analysis(
        ["/tmp/one.pcap", "/tmp/two.pcap"],
        {"do_zeek": True, "llm_enabled": False},
    )

    case = repo.get_case(run["case_id"])
    assert case is not None
    assert case.status.value == "in_progress"
    assert case.tags == ["autosaved", "background"]
    assert len(run["job_ids"]) == 2
    assert queue.submissions[0].options["_origin"] == "streamlit"
    assert queue.submissions[1].options["_batch_index"] == 1


def test_recovery_prefers_active_streamlit_run(tmp_path, monkeypatch):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    old_case = repo.create_case(Case(title="old"))
    active_case = repo.create_case(Case(title="active"))
    old_id = repo.create_job(
        Job(case_id=old_case, pcap_path="/tmp/old.pcap", options_json=json.dumps({"_origin": "streamlit"}))
    )
    repo.update_job_status(old_id, JobStatus.DONE)
    active_id = repo.create_job(
        Job(case_id=active_case, pcap_path="/tmp/new.pcap", options_json=json.dumps({"_origin": "streamlit"}))
    )
    repo.update_job_status(active_id, JobStatus.RUNNING)
    # A non-Streamlit API job must never be attached to the UI session.
    repo.create_job(Job(case_id=active_case, pcap_path="/tmp/api.pcap", options_json="{}"))
    monkeypatch.setattr(bg, "get_background_repo", lambda: repo)

    recovered = bg.find_recoverable_background_run()

    assert recovered["case_id"] == active_case
    assert recovered["job_ids"] == [active_id]
    assert recovered["recovered"] is True


def test_submit_report_reuses_case_and_analysis(tmp_path, monkeypatch):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    queue = _RecordingQueue(repo)
    case_id = repo.create_case(Case(title="report"))
    analysis = Analysis(case_id=case_id, pcap_path="/tmp/report.pcap", features={"flows": []})
    analysis_id = repo.save_analysis(analysis)
    monkeypatch.setattr(bg, "get_background_repo", lambda: repo)
    monkeypatch.setattr(bg, "get_background_queue", lambda: queue)

    run = bg.submit_background_report([analysis_id])

    assert run["case_id"] == case_id
    assert run["report_only"] is True
    assert queue.submissions[0].options["_job_type"] == "llm_report"
    assert queue.submissions[0].options["_analysis_id"] == analysis_id
    assert repo.get_case(case_id).status.value == "in_progress"


def test_completed_job_restores_persisted_analysis(tmp_path, monkeypatch):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    case_id = repo.create_case(Case(title="complete"))
    analysis = Analysis(
        case_id=case_id,
        pcap_path="/tmp/complete.pcap",
        features={"flows": [], "artifacts": {}},
        session_artifacts={"pipeline_stages": ["pyshark_pass"]},
    )
    analysis_id = repo.save_analysis(analysis)
    job_id = repo.create_job(
        Job(
            case_id=case_id,
            pcap_path=analysis.pcap_path,
            options_json=json.dumps({"_origin": "streamlit"}),
        )
    )
    repo.complete_job(job_id, json.dumps({"analysis_id": analysis_id}).encode())

    fake_st = MagicMock()
    fake_st.session_state = {}
    restore = MagicMock()
    monkeypatch.setattr(bg, "get_background_repo", lambda: repo)
    monkeypatch.setattr(bg, "restore_analyses_to_session", restore)
    monkeypatch.setattr(bg, "st", fake_st)
    run = {"case_id": case_id, "job_ids": [job_id], "loaded": False}

    restored = bg.render_background_progress(run)

    assert restored is True
    restore.assert_called_once()
    assert restore.call_args.args[0][0].id == analysis_id
    assert run["loaded"] is True
    assert fake_st.session_state[bg.BACKGROUND_RUN_KEY]["loaded"] is True
    assert repo.get_case(case_id).status.value == "open"
