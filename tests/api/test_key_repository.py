# tests/api/test_key_repository.py
"""Tests for API key repository."""

from __future__ import annotations

from datetime import datetime, timedelta

from app.api.auth import Scope
from app.api.key_models import APIKey, generate_api_key
from app.api.key_repository import KeyRepository


def _repo(tmp_path) -> KeyRepository:
    return KeyRepository(db_path=str(tmp_path / "test_keys.db"))


def _make_key(**overrides) -> tuple[str, APIKey]:
    """Helper: generate a key and return (raw_key, APIKey)."""
    raw, kh, kp = generate_api_key()
    defaults = dict(key_hash=kh, key_prefix=kp, name="test-key", scope=Scope.FEED)
    defaults.update(overrides)
    return raw, APIKey(**defaults)


def test_create_and_get_key(tmp_path):
    repo = _repo(tmp_path)
    raw, key = _make_key(name="splunk-prod")
    kid = repo.create_key(key)
    assert kid.startswith("k_")
    got = repo.get_key_by_id(kid)
    assert got is not None
    assert got.name == "splunk-prod"
    assert got.scope == Scope.FEED


def test_get_key_by_hash(tmp_path):
    repo = _repo(tmp_path)
    raw, key = _make_key()
    repo.create_key(key)
    got = repo.get_key_by_hash(key.key_hash)
    assert got is not None
    assert got.name == key.name


def test_get_key_by_hash_not_found(tmp_path):
    repo = _repo(tmp_path)
    assert repo.get_key_by_hash("nonexistent_hash") is None


def test_list_keys_excludes_revoked(tmp_path):
    repo = _repo(tmp_path)
    _, k1 = _make_key(name="active")
    _, k2 = _make_key(name="revoked")
    repo.create_key(k1)
    id2 = repo.create_key(k2)
    repo.revoke_key(id2)

    keys = repo.list_keys(include_revoked=False)
    names = [k.name for k in keys]
    assert "active" in names
    assert "revoked" not in names

    keys_all = repo.list_keys(include_revoked=True)
    names_all = [k.name for k in keys_all]
    assert "revoked" in names_all


def test_revoke_key(tmp_path):
    repo = _repo(tmp_path)
    _, key = _make_key()
    kid = repo.create_key(key)
    assert repo.revoke_key(kid) is True
    got = repo.get_key_by_id(kid)
    assert got.revoked_at is not None
    assert got.is_active is False


def test_revoke_nonexistent_key(tmp_path):
    repo = _repo(tmp_path)
    assert repo.revoke_key("k_nonexist") is False


def test_update_key_fields(tmp_path):
    repo = _repo(tmp_path)
    _, key = _make_key(name="old-name", scope=Scope.FEED)
    kid = repo.create_key(key)
    updated = repo.update_key(kid, name="new-name", scope="full", rate_limit_rpm=100)
    assert updated is not None
    assert updated.name == "new-name"
    assert updated.scope == Scope.FULL
    assert updated.rate_limit_rpm == 100


def test_update_nonexistent_key(tmp_path):
    repo = _repo(tmp_path)
    assert repo.update_key("k_nonexist", name="x") is None


def test_increment_usage_upsert(tmp_path):
    repo = _repo(tmp_path)
    _, key = _make_key()
    kid = repo.create_key(key)
    repo.increment_usage(kid, "2026-05-23", 5)
    repo.increment_usage(kid, "2026-05-23", 3)
    usage = repo.get_usage(kid, days=30)
    # Should have one entry with 8 total
    day_data = [u for u in usage if u["date"] == "2026-05-23"]
    assert len(day_data) == 1
    assert day_data[0]["requests"] == 8
    # total_requests on key should also be 8
    got = repo.get_key_by_id(kid)
    assert got.total_requests == 8


def test_get_usage_returns_daily_data(tmp_path):
    repo = _repo(tmp_path)
    _, key = _make_key()
    kid = repo.create_key(key)
    repo.increment_usage(kid, "2026-05-22", 10)
    repo.increment_usage(kid, "2026-05-23", 20)
    usage = repo.get_usage(kid, days=30)
    assert len(usage) == 2
    dates = [u["date"] for u in usage]
    assert "2026-05-22" in dates
    assert "2026-05-23" in dates


def test_get_usage_summary(tmp_path):
    repo = _repo(tmp_path)
    _, k1 = _make_key(name="k1")
    _, k2 = _make_key(name="k2")
    id1 = repo.create_key(k1)
    id2 = repo.create_key(k2)
    repo.increment_usage(id1, "2026-05-23", 10)
    repo.increment_usage(id2, "2026-05-23", 5)
    summary = repo.get_usage_summary(days=30)
    day_data = [s for s in summary if s["date"] == "2026-05-23"]
    assert len(day_data) == 1
    assert day_data[0]["requests"] == 15


def test_count_active_keys(tmp_path):
    repo = _repo(tmp_path)
    _, k1 = _make_key(name="active1")
    _, k2 = _make_key(name="active2")
    _, k3 = _make_key(name="revoked")
    repo.create_key(k1)
    repo.create_key(k2)
    id3 = repo.create_key(k3)
    repo.revoke_key(id3)
    assert repo.count_active_keys() == 2


def test_get_expiring_keys(tmp_path):
    repo = _repo(tmp_path)
    _, k1 = _make_key(name="expiring", expires_at=datetime.now() + timedelta(days=3))
    _, k2 = _make_key(name="safe", expires_at=datetime.now() + timedelta(days=30))
    _, k3 = _make_key(name="no-expiry")
    repo.create_key(k1)
    repo.create_key(k2)
    repo.create_key(k3)
    expiring = repo.get_expiring_keys(within_days=7)
    names = [k.name for k in expiring]
    assert "expiring" in names
    assert "safe" not in names
    assert "no-expiry" not in names


def test_schema_idempotent(tmp_path):
    db = str(tmp_path / "idempotent.db")
    KeyRepository(db_path=db)
    repo2 = KeyRepository(db_path=db)  # should not error
    _, key = _make_key()
    kid = repo2.create_key(key)
    assert repo2.get_key_by_id(kid) is not None
