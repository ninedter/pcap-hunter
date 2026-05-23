# tests/api/test_rate_limiter.py
"""Tests for in-memory rate limiter."""

from __future__ import annotations

from app.api.rate_limiter import RateLimiter


def test_allows_under_limit():
    rl = RateLimiter()
    for _ in range(5):
        allowed, _ = rl.check("k1", 10)
        assert allowed is True


def test_blocks_over_limit():
    rl = RateLimiter()
    for _ in range(5):
        rl.check("k1", 5)
    allowed, retry_after = rl.check("k1", 5)
    assert allowed is False
    assert retry_after >= 1


def test_unlimited_key():
    rl = RateLimiter()
    for _ in range(1000):
        allowed, _ = rl.check("k1", None)
        assert allowed is True


def test_retry_after_positive():
    rl = RateLimiter()
    for _ in range(3):
        rl.check("k1", 3)
    _, retry_after = rl.check("k1", 3)
    assert retry_after >= 1
    assert retry_after <= 61


def test_separate_keys_independent():
    rl = RateLimiter()
    for _ in range(5):
        rl.check("k1", 5)
    # k1 is at limit, k2 should still be allowed
    allowed, _ = rl.check("k2", 5)
    assert allowed is True


def test_reset_clears_key():
    rl = RateLimiter()
    for _ in range(5):
        rl.check("k1", 5)
    rl.reset("k1")
    allowed, _ = rl.check("k1", 5)
    assert allowed is True


def test_clear_resets_all():
    rl = RateLimiter()
    for _ in range(5):
        rl.check("k1", 5)
    for _ in range(5):
        rl.check("k2", 5)
    rl.clear()
    allowed1, _ = rl.check("k1", 5)
    allowed2, _ = rl.check("k2", 5)
    assert allowed1 is True
    assert allowed2 is True
