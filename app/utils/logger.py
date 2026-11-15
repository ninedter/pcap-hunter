"""Logging configuration for PCAP Hunter.

Provides both human-readable and structured JSON logging formats.
JSON logging is useful for SIEM ingestion and log aggregation.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for SIEM/log aggregation ingestion.

    Outputs one JSON object per log line with consistent field names:
    ``timestamp``, ``level``, ``logger``, ``message``, plus any extras
    passed via the ``extra`` kwarg on log calls.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Include exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_obj["exception"] = self.formatException(record.exc_info)

        # Merge any structured extras (skip internal LogRecord fields)
        _BUILTIN = {
            "name",
            "msg",
            "args",
            "created",
            "relativeCreated",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "filename",
            "module",
            "pathname",
            "thread",
            "threadName",
            "processName",
            "process",
            "message",
            "levelname",
            "levelno",
            "msecs",
            "taskName",
        }
        for key, value in record.__dict__.items():
            if key not in _BUILTIN and not key.startswith("_"):
                log_obj[key] = value

        return json.dumps(log_obj, default=str)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with consistent formatting.

    The log format is controlled by the ``PCAP_HUNTER_LOG_FORMAT`` environment
    variable:

    - ``"json"`` — structured JSON output (one object per line)
    - anything else (default) — human-readable ``asctime - name - level - message``

    The log level defaults to ``INFO`` and can be overridden with the
    ``PCAP_HUNTER_LOG_LEVEL`` environment variable (e.g. ``DEBUG``, ``WARNING``).

    Dotted (module-level) loggers that receive their own handler stop
    propagating to ancestors: once a parent like ``app`` also has a handler
    (the API process attaches one so logs are visible under uvicorn), every
    record would otherwise emit twice. Top-level names (no dot) keep
    propagating so root-level handlers (e.g. pytest's caplog) still see them.

    Args:
        name: The name of the logger (typically ``__name__``).

    Returns:
        A configured logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()

        log_format = os.getenv("PCAP_HUNTER_LOG_FORMAT", "text").lower()
        if log_format == "json":
            handler.setFormatter(JSONFormatter())
        else:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)

        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        if "." in name:
            logger.propagate = False

        level_name = os.getenv("PCAP_HUNTER_LOG_LEVEL", "INFO").upper()
        logger.setLevel(getattr(logging, level_name, logging.INFO))

    return logger


def streamlit_session_state():
    """Return ``st.session_state`` when Streamlit is already loaded, else ``None``.

    Engine code (pipeline stages, binary discovery, OSINT) runs both inside the
    Streamlit UI and inside headless API / agent workers. This helper never
    imports Streamlit itself: if the hosting process has not imported it, there is
    no session to consult, and importing it here would drag the whole package into
    headless workers (or raise where it is not installed).

    Returns:
        The session-state mapping, or ``None`` when Streamlit is not loaded or
        unusable.
    """
    st = sys.modules.get("streamlit")
    if st is None:
        return None
    try:
        return st.session_state
    except Exception:
        return None


def streamlit_script_context_active() -> bool:
    """Report whether the calling thread runs inside a live Streamlit script run.

    ``st.session_state`` silently degrades to an empty process-global dict when
    there is no ScriptRunContext (bare mode, API workers, pool threads), so a
    ``.get()`` there returns the default rather than the user's setting. Callers
    that must distinguish "setting is off" from "no session here" use this.

    Returns:
        True only when Streamlit is loaded and the current thread has a script context.
    """
    if sys.modules.get("streamlit") is None:
        return False
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx

        return get_script_run_ctx(suppress_warning=True) is not None
    except Exception:
        return False


def log_runtime_error(msg: str):
    """Record a runtime error in the log and, when a UI session exists, its session state.

    Always emits through ``logging`` so headless runs (API / agent workers) keep the
    message. The Streamlit ``runtime_logs`` list is appended to only when Streamlit
    is already loaded in this process — this function never imports it, and never
    raises: it is called from error paths inside pipeline stages.

    Args:
        msg: Human-readable error text.
    """
    logging.getLogger("app.runtime").error("%s", msg)

    state = streamlit_session_state()
    if state is None:
        return
    try:
        if "runtime_logs" not in state:
            state["runtime_logs"] = []
        timestamp = datetime.now().strftime("%H:%M:%S")
        state["runtime_logs"].append(f"[{timestamp}] {msg}")
    except Exception:
        pass  # session state unavailable from this thread — the log record above stands
