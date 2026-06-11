"""Logging configuration for PCAP Hunter.

Provides both human-readable and structured JSON logging formats.
JSON logging is useful for SIEM ingestion and log aggregation.
"""

from __future__ import annotations

import json
import logging
import os
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


def log_runtime_error(msg: str):
    """Log a runtime error to the session state."""
    # Lazy import: this module is also used by the headless API process, which
    # must not drag streamlit in just to get get_logger().
    import streamlit as st

    if "runtime_logs" not in st.session_state:
        st.session_state["runtime_logs"] = []

    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state["runtime_logs"].append(f"[{timestamp}] {msg}")
