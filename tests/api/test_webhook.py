# tests/api/test_webhook.py
"""Tests for the completion-webhook dispatch (Task 4.4, app/api/queue.py).

`_dispatch_webhook` is unit-tested directly (patching `hardened_session` at
its source module so the worker's lazy `from app.security.opsec import
hardened_session` picks up the fake). `_worker_run` integration tests confirm
it is invoked from both terminal branches, guarded by `options["webhook_url"]`.
"""

from __future__ import annotations

import json
import pathlib
from unittest.mock import MagicMock

import pytest

import app.api.queue as queue_mod
from app.api.queue import _dispatch_webhook
from app.database.models import Case, CaseStatus, Job, JobStatus, Severity
from app.database.repository import CaseRepository

FIXTURE_PCAP = pathlib.Path(__file__).parent.parent / "fixtures" / "tiny.pcap"


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Keep the in-loop retry sleep from slowing down the suite."""
    monkeypatch.setattr(queue_mod.time, "sleep", lambda *_a, **_kw: None)


@pytest.fixture(autouse=True)
def _always_safe_url(monkeypatch):
    """Most tests here exercise dispatch/retry logic, not the SSRF guard itself."""
    monkeypatch.setattr("app.utils.network_utils.is_safe_webhook_url", lambda url: True)


# ---------------------------------------------------------------------------
# _dispatch_webhook unit tests
# ---------------------------------------------------------------------------


def test_dispatch_webhook_posts_expected_envelope(monkeypatch):
    captured = {}

    def fake_hardened_session(timeout):
        captured["timeout"] = timeout
        session = MagicMock()

        def post(url, data=None, headers=None, **kwargs):
            captured["url"] = url
            captured["data"] = data
            captured["headers"] = headers
            return MagicMock(status_code=200)

        session.post = post
        return session

    monkeypatch.setattr("app.security.opsec.hardened_session", fake_hardened_session)

    payload = {"job_id": "j_abc12345", "case_id": "cafe0001", "status": "done", "analysis_id": "an_1"}
    _dispatch_webhook("https://example.com/hook", payload, timeout=7, max_retries=2)

    assert captured["url"] == "https://example.com/hook"
    assert captured["timeout"] == 7
    assert json.loads(captured["data"]) == payload
    assert captured["headers"]["Content-Type"] == "application/json"


def test_dispatch_webhook_does_not_follow_redirects(monkeypatch):
    """A 302 to an internal host must NOT be followed -- the SSRF guard only
    validated the original URL, so redirects would reopen the SSRF hole.
    The POST must pass allow_redirects=False."""
    captured = {}
    calls = {"n": 0}

    def fake_hardened_session(timeout):
        session = MagicMock()

        def post(url, data=None, headers=None, allow_redirects=None, **kwargs):
            calls["n"] += 1
            captured["allow_redirects"] = allow_redirects
            captured["url"] = url
            # A malicious receiver tries to bounce us to the cloud metadata endpoint.
            return MagicMock(status_code=302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

        session.post = post
        return session

    monkeypatch.setattr("app.security.opsec.hardened_session", fake_hardened_session)

    _dispatch_webhook("https://example.com/hook", {"a": 1}, timeout=5, max_retries=0)

    assert captured["allow_redirects"] is False, "webhook POST must disable redirect-following"
    # Only the original (validated) URL was ever requested; the 302 Location was not chased.
    assert calls["n"] == 1
    assert captured["url"] == "https://example.com/hook"


def test_dispatch_webhook_retries_up_to_max_retries_on_failure(monkeypatch):
    calls = {"n": 0}

    def fake_hardened_session(timeout):
        session = MagicMock()

        def post(url, data=None, headers=None, **kwargs):
            calls["n"] += 1
            return MagicMock(status_code=500)

        session.post = post
        return session

    monkeypatch.setattr("app.security.opsec.hardened_session", fake_hardened_session)

    _dispatch_webhook("https://example.com/hook", {"a": 1}, timeout=5, max_retries=2)

    assert calls["n"] == 3  # 1 initial attempt + 2 retries


def test_dispatch_webhook_stops_retrying_once_a_2xx_is_seen(monkeypatch):
    calls = {"n": 0}

    def fake_hardened_session(timeout):
        session = MagicMock()

        def post(url, data=None, headers=None, **kwargs):
            calls["n"] += 1
            return MagicMock(status_code=200)

        session.post = post
        return session

    monkeypatch.setattr("app.security.opsec.hardened_session", fake_hardened_session)

    _dispatch_webhook("https://example.com/hook", {"a": 1}, timeout=5, max_retries=3)

    assert calls["n"] == 1


def test_dispatch_webhook_never_raises_when_session_construction_throws(monkeypatch):
    def fake_hardened_session(timeout):
        raise RuntimeError("network is down")

    monkeypatch.setattr("app.security.opsec.hardened_session", fake_hardened_session)

    # Must not raise -- a webhook failure must never affect the job's own status.
    _dispatch_webhook("https://example.com/hook", {"a": 1}, timeout=5, max_retries=1)


def test_dispatch_webhook_never_raises_when_post_throws_every_attempt(monkeypatch):
    def fake_hardened_session(timeout):
        session = MagicMock()
        session.post.side_effect = ConnectionError("boom")
        return session

    monkeypatch.setattr("app.security.opsec.hardened_session", fake_hardened_session)

    _dispatch_webhook("https://example.com/hook", {"a": 1}, timeout=5, max_retries=2)


def test_dispatch_webhook_never_raises_when_lazy_import_fails(monkeypatch):
    """The lazy `from app.security.opsec import ...` lives INSIDE the try, so an
    import failure is swallowed too. If it escaped, it would propagate into
    _worker_run's `except` and flip an already-DONE job to FAILED."""
    import sys

    # Poisoning sys.modules makes `from app.security.opsec import ...` raise
    # ModuleNotFoundError -- the very first statement inside _dispatch_webhook's try.
    monkeypatch.setitem(sys.modules, "app.security.opsec", None)

    # Must return, not raise, even though the import blew up.
    _dispatch_webhook("https://example.com/hook", {"a": 1}, timeout=5, max_retries=1)


def test_dispatch_webhook_refuses_unsafe_url_without_posting(monkeypatch):
    monkeypatch.setattr("app.utils.network_utils.is_safe_webhook_url", lambda url: False)

    session = MagicMock()
    monkeypatch.setattr("app.security.opsec.hardened_session", lambda timeout: session)

    _dispatch_webhook("http://10.0.0.5/hook", {"a": 1}, timeout=5, max_retries=2)

    session.post.assert_not_called()


# ---------------------------------------------------------------------------
# _worker_run integration: webhook fires on both terminal branches
# ---------------------------------------------------------------------------


def _fake_pipeline_result(case_id):
    from app.pipeline.runner import PipelineResult

    return PipelineResult(
        case_id=case_id,
        packet_count=1,
        features={"flows": [], "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []}},
    )


def test_worker_fires_webhook_on_success(tmp_path, monkeypatch):
    import app.pipeline.runner as runner_mod

    captured = {}

    def fake_dispatch(url, payload, timeout, max_retries):
        captured.update(url=url, payload=payload, timeout=timeout, max_retries=max_retries)

    monkeypatch.setattr(queue_mod, "_dispatch_webhook", fake_dispatch)
    monkeypatch.setenv("PCAP_HUNTER_API_WEBHOOK_TIMEOUT_SECONDS", "3")
    monkeypatch.setenv("PCAP_HUNTER_API_WEBHOOK_MAX_RETRIES", "1")
    monkeypatch.setattr(
        runner_mod,
        "run_pipeline",
        lambda pcap_path, case_id, options, progress, heartbeat=None: (_fake_pipeline_result(case_id)),
    )

    fake_pcap = tmp_path / "fake.pcap"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0099", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0099", pcap_path=str(fake_pcap), options_json="{}"))

    queue_mod._worker_run(
        job_id,
        db,
        str(fake_pcap),
        {"osint_enabled": False, "llm_enabled": False, "webhook_url": "https://example.com/hook"},
    )

    job = repo.get_job(job_id)
    assert job.status == JobStatus.DONE
    assert captured["url"] == "https://example.com/hook"
    assert captured["payload"]["job_id"] == job_id
    assert captured["payload"]["case_id"] == "cafe0099"
    assert captured["payload"]["status"] == "done"
    assert captured["timeout"] == 3
    assert captured["max_retries"] == 1


def test_worker_fires_webhook_on_failure(tmp_path, monkeypatch):
    import app.pipeline.runner as runner_mod

    captured = {}

    def fake_dispatch(url, payload, timeout, max_retries):
        captured["payload"] = payload

    monkeypatch.setattr(queue_mod, "_dispatch_webhook", fake_dispatch)

    def boom(*a, **kw):
        raise RuntimeError("pipeline exploded")

    monkeypatch.setattr(runner_mod, "run_pipeline", boom)

    fake_pcap = tmp_path / "fake.pcap"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0098", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0098", pcap_path=str(fake_pcap), options_json="{}"))

    queue_mod._worker_run(
        job_id,
        db,
        str(fake_pcap),
        {"osint_enabled": False, "llm_enabled": False, "webhook_url": "https://example.com/hook"},
    )

    job = repo.get_job(job_id)
    assert job.status == JobStatus.FAILED
    assert captured["payload"]["status"] == "failed"
    assert captured["payload"]["analysis_id"] is None
    assert captured["payload"]["case_id"] == "cafe0098"


def test_worker_does_not_fire_webhook_when_not_configured(tmp_path, monkeypatch):
    import app.pipeline.runner as runner_mod

    called = {"n": 0}
    monkeypatch.setattr(queue_mod, "_dispatch_webhook", lambda *a, **kw: called.__setitem__("n", called["n"] + 1))
    monkeypatch.setattr(
        runner_mod,
        "run_pipeline",
        lambda pcap_path, case_id, options, progress, heartbeat=None: (_fake_pipeline_result(case_id)),
    )

    fake_pcap = tmp_path / "fake.pcap"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    db = str(tmp_path / "t.db")
    repo = CaseRepository(db_path=db)
    repo.create_case(Case(id="cafe0097", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    job_id = repo.create_job(Job(case_id="cafe0097", pcap_path=str(fake_pcap), options_json="{}"))

    queue_mod._worker_run(job_id, db, str(fake_pcap), {"osint_enabled": False, "llm_enabled": False})

    assert called["n"] == 0
