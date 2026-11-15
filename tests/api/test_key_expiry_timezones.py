"""API key expiry must never mix naive and offset-aware datetimes."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.key_models import APIKey, as_aware, parse_key_timestamp, to_stored_local


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))
    from app.api.deps import get_key_repo, get_queue, get_rate_limiter, get_repo, get_settings, get_usage_tracker

    getters = (get_settings, get_repo, get_queue, get_key_repo, get_rate_limiter, get_usage_tracker)
    for getter in getters:
        getter.cache_clear()
    from app.api.app import create_app

    yield TestClient(create_app())
    for getter in getters:
        getter.cache_clear()


AUTH = {"Authorization": "Bearer MAIN"}


def _create(client, scope="feed") -> dict:
    response = client.post("/api/v1/admin/keys", json={"name": "k", "scope": scope}, headers=AUTH)
    assert response.status_code == 201
    return response.json()


@pytest.mark.parametrize(
    "expires_at",
    ["2099-01-01T00:00:00Z", "2099-01-01T00:00:00+00:00", "2099-01-01T08:00:00+08:00", "2099-01-01T00:00:00"],
)
def test_future_expiry_in_any_iso_form_keeps_the_key_usable(client, expires_at):
    key = _create(client)

    patched = client.patch(f"/api/v1/admin/keys/{key['id']}", json={"expires_at": expires_at}, headers=AUTH)
    assert patched.status_code == 200, patched.text
    assert patched.json()["status"] == "active"

    # Every request made with the key used to 500 on a TypeError here.
    used = client.get("/api/v1/iocs.json", headers={"Authorization": f"Bearer {key['key']}"})
    assert used.status_code == 200, used.text
    listing = client.get("/api/v1/admin/keys", headers=AUTH)
    assert listing.status_code == 200, listing.text
    assert client.get(f"/api/v1/admin/keys/{key['id']}", headers=AUTH).status_code == 200


@pytest.mark.parametrize("expires_at", ["2020-01-01T00:00:00Z", "2020-01-01T00:00:00-11:00", "2020-01-01T00:00:00"])
def test_past_expiry_in_any_iso_form_rejects_the_key_with_401(client, expires_at):
    key = _create(client)
    assert (
        client.patch(f"/api/v1/admin/keys/{key['id']}", json={"expires_at": expires_at}, headers=AUTH).status_code
        == 200
    )

    used = client.get("/api/v1/iocs.json", headers={"Authorization": f"Bearer {key['key']}"})
    assert used.status_code == 401
    assert client.get(f"/api/v1/admin/keys/{key['id']}", headers=AUTH).json()["status"] == "expired"


def test_offset_expiry_is_stored_as_the_same_instant(client):
    key = _create(client)
    client.patch(f"/api/v1/admin/keys/{key['id']}", json={"expires_at": "2099-06-01T12:00:00+08:00"}, headers=AUTH)

    from app.api.deps import get_key_repo

    stored = get_key_repo().get_key_by_id(key["id"]).expires_at
    assert stored.tzinfo is None, "one stored form: naive local time"
    assert as_aware(stored) == datetime(2099, 6, 1, 4, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("expires_at", ["tomorrow", "2027-13-45", "", "2027-01-01T25:00:00Z"])
def test_unparseable_expiry_is_rejected_with_422(client, expires_at):
    key = _create(client)

    response = client.patch(f"/api/v1/admin/keys/{key['id']}", json={"expires_at": expires_at}, headers=AUTH)

    assert response.status_code == 422
    assert response.json()["code"] == "invalid_expires_at"
    assert client.get(f"/api/v1/admin/keys/{key['id']}", headers=AUTH).json()["expires_at"] is None


def test_offset_aware_value_already_in_the_database_no_longer_breaks_requests(client, tmp_path):
    """A row written by the old PATCH keeps working without any migration."""
    key = _create(client, scope="full")
    conn = sqlite3.connect(tmp_path / "t.db")
    conn.execute("UPDATE api_keys SET expires_at='2099-01-01T00:00:00+00:00' WHERE id=?", (key["id"],))
    conn.commit()
    conn.close()

    assert client.get("/api/v1/admin/keys", headers={"Authorization": f"Bearer {key['key']}"}).status_code == 200
    listed = client.get("/api/v1/admin/keys", headers=AUTH).json()
    assert [row["status"] for row in listed if row["id"] == key["id"]] == ["active"]

    from app.api.deps import get_key_repo

    assert get_key_repo().count_active_keys(scope="full") == 1
    assert get_key_repo().get_expiring_keys(within_days=7) == []


def test_unreadable_stored_expiry_fails_closed_without_a_500(client, tmp_path):
    key = _create(client)
    conn = sqlite3.connect(tmp_path / "t.db")
    conn.execute("UPDATE api_keys SET expires_at='not-a-date' WHERE id=?", (key["id"],))
    conn.commit()
    conn.close()

    assert client.get("/api/v1/iocs.json", headers={"Authorization": f"Bearer {key['key']}"}).status_code == 401
    assert client.get("/api/v1/admin/keys", headers=AUTH).status_code == 200


def test_counts_and_expiring_window_mix_naive_and_aware_rows(tmp_path):
    from app.api.auth import Scope
    from app.api.key_repository import KeyRepository

    repo = KeyRepository(db_path=str(tmp_path / "k.db"))
    now_local = datetime.now()
    now_utc = datetime.now(timezone.utc)
    rows = {
        "naive-soon": now_local + timedelta(days=2),
        "aware-soon": now_utc + timedelta(days=3),
        "aware-later": now_utc + timedelta(days=40),
        "aware-past": now_utc - timedelta(hours=1),
        "naive-past": now_local - timedelta(hours=1),
    }
    for index, (name, expires_at) in enumerate(rows.items()):
        repo.create_key(APIKey(key_hash=f"h{index}", key_prefix="phk_test", name=name, scope=Scope.FULL))
        with repo._get_conn() as conn:  # store the raw text, as a pre-fix PATCH would have
            conn.execute("UPDATE api_keys SET expires_at=? WHERE name=?", (expires_at.isoformat(), name))
            conn.commit()

    assert repo.count_active_keys() == 3
    assert repo.count_active_keys(scope="full") == 3
    assert [key.name for key in repo.get_expiring_keys(within_days=7)] == ["naive-soon", "aware-soon"]


def test_status_properties_accept_both_forms():
    soon = datetime.now(timezone.utc) + timedelta(days=1)
    assert APIKey(expires_at=soon).status == "expiring_soon"
    assert APIKey(expires_at=soon.astimezone().replace(tzinfo=None)).status == "expiring_soon"
    assert APIKey(expires_at=datetime.now(timezone.utc) - timedelta(seconds=5)).is_active is False
    assert APIKey(expires_at=datetime.now() + timedelta(days=30)).status == "active"


def test_boundary_helpers_round_trip():
    aware = datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert as_aware(to_stored_local(aware)) == aware
    assert parse_key_timestamp("2030-01-01T00:00:00Z") == to_stored_local(aware)
    naive = datetime(2030, 1, 1, 9, 30)
    assert to_stored_local(naive) is naive
    with pytest.raises(ValueError):
        parse_key_timestamp("   ")


# ---- Out-of-range expiry values ("never" sentinels) -----------------------

OUT_OF_RANGE = [
    "9999-12-31T23:59:59",
    "9999-12-31T23:59:59Z",
    "9999-12-31T23:59:59-11:00",
    "9000-01-01T00:00:00",
    "0001-01-01T00:00:00",
    "0001-01-01T00:00:00+14:00",
    "1970-12-31T23:59:59",
]


@pytest.fixture(params=["Asia/Taipei", "America/Los_Angeles", "UTC"])
def host_timezone(request, monkeypatch):
    """Force the process timezone to a positive, a negative and a zero UTC offset."""
    import time

    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset is POSIX-only")
    monkeypatch.setenv("TZ", request.param)
    time.tzset()
    yield request.param
    monkeypatch.undo()
    time.tzset()


@pytest.mark.parametrize("expires_at", OUT_OF_RANGE)
def test_out_of_range_expiry_is_rejected_at_the_boundary(host_timezone, client, expires_at):
    key = _create(client)

    response = client.patch(f"/api/v1/admin/keys/{key['id']}", json={"expires_at": expires_at}, headers=AUTH)

    assert response.status_code == 422, response.text
    assert response.json()["code"] == "invalid_expires_at"
    assert client.get(f"/api/v1/admin/keys/{key['id']}", headers=AUTH).json()["expires_at"] is None


@pytest.mark.parametrize("expires_at", ["1971-01-02T00:00:00Z", "8999-12-30T00:00:00Z", "2099-01-01T00:00:00"])
def test_values_inside_the_documented_range_are_accepted(host_timezone, client, expires_at):
    key = _create(client)

    response = client.patch(f"/api/v1/admin/keys/{key['id']}", json={"expires_at": expires_at}, headers=AUTH)

    assert response.status_code == 200, response.text
    assert client.get("/api/v1/admin/keys", headers=AUTH).status_code == 200


@pytest.mark.parametrize("stored", ["9999-12-31T23:59:59", "0001-01-01T00:00:00", "9999-12-31T23:59:59+00:00"])
def test_bad_row_already_in_the_database_expires_only_that_key(host_timezone, client, tmp_path, stored):
    bad = _create(client, scope="full")
    good = _create(client, scope="full")
    conn = sqlite3.connect(tmp_path / "t.db")
    conn.execute("UPDATE api_keys SET expires_at=? WHERE id=?", (stored, bad["id"]))
    conn.commit()
    conn.close()

    from app.api.app import create_app
    from app.api.deps import get_key_repo

    repo = get_key_repo()
    assert repo.count_active_keys() == 1  # used to raise "year 10000 is out of range"
    assert repo.count_active_keys(scope="full") == 1
    assert repo.get_expiring_keys(within_days=7) == []
    rebooted = TestClient(create_app())  # the application still boots with the bad row present
    listing = rebooted.get("/api/v1/admin/keys", headers=AUTH)
    assert listing.status_code == 200, listing.text
    statuses = {row["id"]: row["status"] for row in listing.json()}
    assert statuses[bad["id"]] == "expired" and statuses[good["id"]] == "active"
    assert rebooted.get("/api/v1/iocs.json", headers={"Authorization": f"Bearer {bad['key']}"}).status_code == 401
    assert rebooted.get("/api/v1/iocs.json", headers={"Authorization": f"Bearer {good['key']}"}).status_code == 200


def test_in_memory_key_with_an_unrepresentable_expiry_reads_as_expired(host_timezone):
    for value in (datetime(9999, 12, 31, 23, 59, 59), datetime(1, 1, 1), datetime(9999, 12, 31, tzinfo=timezone.utc)):
        key = APIKey(expires_at=value)
        assert key.is_active is False and key.status == "expired"
        assert key.to_dict()["status"] == "expired"
