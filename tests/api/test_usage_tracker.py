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
    # Failed entries are restored for retry on next flush
    assert ut.get_pending_count("k1") == 1


def test_flush_partial_failure_restores_only_failed():
    """When some keys succeed and others fail, only failed entries are restored."""
    ut = UsageTracker()
    ut.record("ok_key")
    ut.record("bad_key")

    mock_repo = MagicMock()

    def selective_fail(key_id, date_str, count=1):
        if key_id == "bad_key":
            raise Exception("db error")

    mock_repo.increment_usage.side_effect = selective_fail
    ut.flush(mock_repo)

    assert ut.get_pending_count("ok_key") == 0
    assert ut.get_pending_count("bad_key") == 1


def test_pending_count_unknown_key():
    ut = UsageTracker()
    assert ut.get_pending_count("nonexistent") == 0
