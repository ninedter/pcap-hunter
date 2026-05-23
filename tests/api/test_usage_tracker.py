# tests/api/test_usage_tracker.py
"""Tests for usage tracker."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.api.usage_tracker import UsageTracker


def test_record_increments_count():
    ut = UsageTracker()
    ut.record("k1")
    ut.record("k1")
    ut.record("k2")
    assert ut.get_pending_count("k1") == 2
    assert ut.get_pending_count("k2") == 1


def test_flush_writes_to_repo():
    ut = UsageTracker()
    ut.record("k1")
    ut.record("k1")
    ut.record("k2")

    mock_repo = MagicMock()
    ut.flush(mock_repo)

    # Should have called increment_usage for each key
    assert mock_repo.increment_usage.call_count == 2
    assert mock_repo.touch_key_last_used.call_count == 2

    # After flush, counts should be zero
    assert ut.get_pending_count("k1") == 0
    assert ut.get_pending_count("k2") == 0


def test_flush_empty_is_noop():
    ut = UsageTracker()
    mock_repo = MagicMock()
    ut.flush(mock_repo)
    mock_repo.increment_usage.assert_not_called()


def test_flush_handles_repo_error():
    ut = UsageTracker()
    ut.record("k1")

    mock_repo = MagicMock()
    mock_repo.increment_usage.side_effect = Exception("db error")
    # Should not raise
    ut.flush(mock_repo)
    # Counts should still be cleared (we don't retry)
    assert ut.get_pending_count("k1") == 0


def test_pending_count_unknown_key():
    ut = UsageTracker()
    assert ut.get_pending_count("nonexistent") == 0
