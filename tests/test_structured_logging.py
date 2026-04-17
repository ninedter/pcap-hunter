"""Tests for structured JSON logging and logger configuration."""

from __future__ import annotations

import json
import logging
import os
from unittest.mock import patch

from app.utils.logger import JSONFormatter, get_logger


class TestJSONFormatter:
    def test_basic_format(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Hello %s",
            args=("world",),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["logger"] == "test.logger"
        assert data["message"] == "Hello world"
        assert "timestamp" in data
        assert "+00:00" in data["timestamp"] or data["timestamp"].endswith("Z")

    def test_exception_included(self):
        formatter = JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys

            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="Failed",
                args=(),
                exc_info=sys.exc_info(),
            )
        output = formatter.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert "ValueError" in data["exception"]

    def test_extra_fields(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="event",
            args=(),
            exc_info=None,
        )
        # Simulate extra fields
        record.ip_address = "1.2.3.4"
        record.provider = "greynoise"
        output = formatter.format(record)
        data = json.loads(output)
        assert data["ip_address"] == "1.2.3.4"
        assert data["provider"] == "greynoise"


class TestGetLogger:
    def test_returns_logger(self):
        # Remove any existing handlers to test fresh
        logger_name = "test.fresh.logger"
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()

        result = get_logger(logger_name)
        assert isinstance(result, logging.Logger)
        assert result.name == logger_name

    @patch.dict(os.environ, {"PCAP_HUNTER_LOG_FORMAT": "json"})
    def test_json_format_env(self):
        logger_name = "test.json.env"
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()

        result = get_logger(logger_name)
        assert len(result.handlers) == 1
        assert isinstance(result.handlers[0].formatter, JSONFormatter)

    @patch.dict(os.environ, {"PCAP_HUNTER_LOG_LEVEL": "DEBUG"})
    def test_log_level_env(self):
        logger_name = "test.level.env"
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()

        result = get_logger(logger_name)
        assert result.level == logging.DEBUG

    def test_default_text_format(self):
        logger_name = "test.default.format"
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()

        # Ensure env var is not set to json
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PCAP_HUNTER_LOG_FORMAT", None)
            result = get_logger(logger_name)
            assert len(result.handlers) == 1
            assert not isinstance(result.handlers[0].formatter, JSONFormatter)
