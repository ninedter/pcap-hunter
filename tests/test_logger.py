# tests/test_logger.py
"""Tests for app.utils.logger — runtime error log, idempotent handler setup, lazy streamlit import."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import streamlit as st

from app.utils.logger import log_runtime_error


def test_log_runtime_error():
    # Mock session state if needed, but streamlit usually handles it in tests if configured right.
    # If not, we might need to mock st.session_state.
    # Streamlit's session state is a bit tricky in tests without streamlit context.
    # But let's try basic usage.

    # Reset
    if "runtime_logs" in st.session_state:
        del st.session_state["runtime_logs"]

    log_runtime_error("Test error")

    assert "runtime_logs" in st.session_state
    assert len(st.session_state["runtime_logs"]) == 1
    assert "Test error" in st.session_state["runtime_logs"][0]


def test_get_logger_is_idempotent():
    from app.utils.logger import get_logger

    lg1 = get_logger("app.test_idem")
    lg2 = get_logger("app.test_idem")
    assert lg1 is lg2
    assert len(lg1.handlers) == 1


def test_single_emission_per_record_with_app_handler():
    """No double-logging once the 'app' logger has a handler (the uvicorn/API path).

    Self-handled module loggers (get_logger(__name__)) must emit exactly once via
    their own handler; plain getLogger children (audit middleware style) must emit
    exactly once via propagation to the 'app' handler.
    """
    import logging

    from app.utils.logger import get_logger

    get_logger("app")
    selfhandled = get_logger("app.test_dup.selfhandled")
    plain = logging.getLogger("app.test_dup.plain")  # audit-middleware style: no own handler

    hits: list[str] = []

    class _Counter(logging.Filter):
        def __init__(self, tag: str) -> None:
            super().__init__()
            self.tag = tag

        def filter(self, record: logging.LogRecord) -> bool:
            hits.append(self.tag)
            return True

    attached: list[tuple[logging.Handler, logging.Filter]] = []
    for tag, lg in (("app", logging.getLogger("app")), ("selfhandled", selfhandled)):
        for handler in lg.handlers:
            counter = _Counter(tag)
            handler.addFilter(counter)
            attached.append((handler, counter))
    try:
        selfhandled.warning("probe-selfhandled")
        assert hits == ["selfhandled"], hits

        hits.clear()
        plain.warning("probe-plain")
        assert hits == ["app"], hits
    finally:
        for handler, counter in attached:
            handler.removeFilter(counter)


def test_import_does_not_pull_streamlit():
    """Importing app.utils.logger must not import streamlit.

    The headless API process imports get_logger via key_repository — a module-level
    streamlit import here would drag the whole streamlit package into uvicorn workers.
    """
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    code = "import sys; import app.utils.logger; sys.exit(1 if 'streamlit' in sys.modules else 0)"
    env = dict(os.environ, PYTHONPATH=str(repo_root))
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"streamlit was imported transitively\nstderr: {result.stderr}"
