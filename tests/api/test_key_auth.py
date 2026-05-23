# tests/api/test_key_auth.py
"""Tests for DB-aware auth flow."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

import pytest

from app.api.auth import Scope
from app.api.key_auth import RateLimitError, authenticate
from app.api.key_models import APIKey
from app.api.key_repository import KeyRepository
from app.api.rate_limiter import RateLimiter
from app.api.settings import APISettings
from app.api.usage_tracker import UsageTracker


def _settings(main="MAIN", feed="FEED") -> APISettings:
    return APISettings(
        main_key=main,
        feed_key=feed,
        host="127.0.0.1",
        port=8000,
        workers=1,
        queue_depth=10,
        max_pcap_bytes=10**9,
        upload_timeout_seconds=60,
        pcap_ttl_days=1,
        artifact_ttl_days=2,
        job_ttl_days=3,
        require_https=False,
        cors_origins=[],
    )


def _deps(tmp_path):
    repo = KeyRepository(db_path=str(tmp_path / "keys.db"))
    return repo, RateLimiter(), UsageTracker()


class TestEnvKeyAuth:
    """Tests for environment-variable key authentication."""

    def test_env_main_key(self, tmp_path):
        settings = _settings()
        repo, rl, ut = _deps(tmp_path)
        result = authenticate("Bearer MAIN", settings, repo, rl, ut, Scope.FULL)
        assert result.scope == Scope.FULL
        assert result.source == "env:main"
        assert result.api_key is None

    def test_env_feed_key(self, tmp_path):
        settings = _settings()
        repo, rl, ut = _deps(tmp_path)
        result = authenticate("Bearer FEED", settings, repo, rl, ut, Scope.FEED)
        assert result.scope == Scope.FEED
        assert result.source == "env:feed"

    def test_env_main_key_can_access_feed(self, tmp_path):
        settings = _settings()
        repo, rl, ut = _deps(tmp_path)
        result = authenticate("Bearer MAIN", settings, repo, rl, ut, Scope.FEED)
        assert result.scope == Scope.FULL

    def test_env_keys_not_rate_limited(self, tmp_path):
        settings = _settings()
        repo, rl, ut = _deps(tmp_path)
        for _ in range(100):
            result = authenticate("Bearer MAIN", settings, repo, rl, ut, Scope.FULL)
            assert result.scope == Scope.FULL


class TestDbKeyAuth:
    """Tests for database-backed key authentication."""

    def test_db_key_lookup(self, tmp_path):
        settings = _settings(main=None, feed=None)
        repo, rl, ut = _deps(tmp_path)
        raw_key = "phk_testkey123456789012345678"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = APIKey(key_hash=key_hash, key_prefix=raw_key[:8], name="db-test", scope=Scope.FULL)
        repo.create_key(api_key)
        result = authenticate(f"Bearer {raw_key}", settings, repo, rl, ut, Scope.FULL)
        assert result.scope == Scope.FULL
        assert result.source == "db"
        assert result.key_name == "db-test"

    def test_db_key_records_usage(self, tmp_path):
        settings = _settings(main=None, feed=None)
        repo, rl, ut = _deps(tmp_path)
        raw_key = "phk_usagetrack1234567890123456"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = APIKey(key_hash=key_hash, key_prefix=raw_key[:8], name="tracked", scope=Scope.FULL)
        repo.create_key(api_key)
        authenticate(f"Bearer {raw_key}", settings, repo, rl, ut, Scope.FULL)
        assert ut.get_pending_count(api_key.id) == 1


class TestAuthErrors:
    """Tests for authentication error cases."""

    def test_invalid_key_raises(self, tmp_path):
        settings = _settings()
        repo, rl, ut = _deps(tmp_path)
        with pytest.raises(ValueError, match="invalid_key"):
            authenticate("Bearer WRONG", settings, repo, rl, ut, Scope.FULL)

    def test_missing_auth_raises(self, tmp_path):
        settings = _settings()
        repo, rl, ut = _deps(tmp_path)
        with pytest.raises(ValueError, match="missing_or_malformed_auth"):
            authenticate(None, settings, repo, rl, ut, Scope.FULL)

    def test_empty_bearer_raises(self, tmp_path):
        settings = _settings()
        repo, rl, ut = _deps(tmp_path)
        with pytest.raises(ValueError, match="missing_or_malformed_auth"):
            authenticate("Bearer ", settings, repo, rl, ut, Scope.FULL)

    def test_non_bearer_scheme_raises(self, tmp_path):
        settings = _settings()
        repo, rl, ut = _deps(tmp_path)
        with pytest.raises(ValueError, match="missing_or_malformed_auth"):
            authenticate("Basic dXNlcjpwYXNz", settings, repo, rl, ut, Scope.FULL)

    def test_expired_key_raises(self, tmp_path):
        settings = _settings(main=None, feed=None)
        repo, rl, ut = _deps(tmp_path)
        raw_key = "phk_expired1234567890123456789"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = APIKey(
            key_hash=key_hash,
            key_prefix=raw_key[:8],
            name="expired",
            scope=Scope.FULL,
            expires_at=datetime.now() - timedelta(days=1),
        )
        repo.create_key(api_key)
        with pytest.raises(ValueError, match="key_expired"):
            authenticate(f"Bearer {raw_key}", settings, repo, rl, ut, Scope.FULL)

    def test_revoked_key_raises(self, tmp_path):
        settings = _settings(main=None, feed=None)
        repo, rl, ut = _deps(tmp_path)
        raw_key = "phk_revoked1234567890123456789"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = APIKey(key_hash=key_hash, key_prefix=raw_key[:8], name="revoked", scope=Scope.FULL)
        kid = repo.create_key(api_key)
        repo.revoke_key(kid)
        with pytest.raises(ValueError, match="key_revoked"):
            authenticate(f"Bearer {raw_key}", settings, repo, rl, ut, Scope.FULL)


class TestScopeEnforcement:
    """Tests for scope-based access control."""

    def test_feed_key_cannot_access_full(self, tmp_path):
        settings = _settings(main=None, feed=None)
        repo, rl, ut = _deps(tmp_path)
        raw_key = "phk_feedonly123456789012345678"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = APIKey(key_hash=key_hash, key_prefix=raw_key[:8], name="feed-only", scope=Scope.FEED)
        repo.create_key(api_key)
        with pytest.raises(PermissionError):
            authenticate(f"Bearer {raw_key}", settings, repo, rl, ut, Scope.FULL)

    def test_full_key_can_access_feed(self, tmp_path):
        settings = _settings(main=None, feed=None)
        repo, rl, ut = _deps(tmp_path)
        raw_key = "phk_fullscope12345678901234567"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = APIKey(key_hash=key_hash, key_prefix=raw_key[:8], name="full-scope", scope=Scope.FULL)
        repo.create_key(api_key)
        result = authenticate(f"Bearer {raw_key}", settings, repo, rl, ut, Scope.FEED)
        assert result.scope == Scope.FULL

    def test_env_feed_key_cannot_access_full(self, tmp_path):
        settings = _settings()
        repo, rl, ut = _deps(tmp_path)
        with pytest.raises(PermissionError):
            authenticate("Bearer FEED", settings, repo, rl, ut, Scope.FULL)


class TestRateLimiting:
    """Tests for rate limit enforcement."""

    def test_rate_limit_returns_error(self, tmp_path):
        settings = _settings(main=None, feed=None)
        repo, rl, ut = _deps(tmp_path)
        raw_key = "phk_ratelimited12345678901234"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = APIKey(
            key_hash=key_hash,
            key_prefix=raw_key[:8],
            name="limited",
            scope=Scope.FULL,
            rate_limit_rpm=2,
        )
        repo.create_key(api_key)
        # First 2 should succeed
        authenticate(f"Bearer {raw_key}", settings, repo, rl, ut, Scope.FULL)
        authenticate(f"Bearer {raw_key}", settings, repo, rl, ut, Scope.FULL)
        # Third should fail
        with pytest.raises(RateLimitError):
            authenticate(f"Bearer {raw_key}", settings, repo, rl, ut, Scope.FULL)

    def test_rate_limit_error_has_retry_after(self, tmp_path):
        settings = _settings(main=None, feed=None)
        repo, rl, ut = _deps(tmp_path)
        raw_key = "phk_retryafter12345678901234567"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = APIKey(
            key_hash=key_hash,
            key_prefix=raw_key[:8],
            name="retry-check",
            scope=Scope.FULL,
            rate_limit_rpm=1,
        )
        repo.create_key(api_key)
        authenticate(f"Bearer {raw_key}", settings, repo, rl, ut, Scope.FULL)
        with pytest.raises(RateLimitError) as exc_info:
            authenticate(f"Bearer {raw_key}", settings, repo, rl, ut, Scope.FULL)
        assert exc_info.value.retry_after >= 1

    def test_no_rate_limit_when_rpm_is_none(self, tmp_path):
        settings = _settings(main=None, feed=None)
        repo, rl, ut = _deps(tmp_path)
        raw_key = "phk_unlimited12345678901234567"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = APIKey(
            key_hash=key_hash,
            key_prefix=raw_key[:8],
            name="unlimited",
            scope=Scope.FULL,
            rate_limit_rpm=None,
        )
        repo.create_key(api_key)
        for _ in range(50):
            authenticate(f"Bearer {raw_key}", settings, repo, rl, ut, Scope.FULL)
