"""STIX escaping, UTC timestamps, cursor validation and instant-based ``since`` for the IOC feed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.routers.iocs import _row_to_stix_pattern, _stix_timestamp, _to_stix_bundle
from app.database.models import IOC, Analysis, Case, IOCType, Severity

FEED = {"Authorization": "Bearer FEED"}


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_FEED_KEY", "FEED")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))
    from app.api.deps import get_queue, get_repo, get_settings

    for getter in (get_settings, get_repo, get_queue):
        getter.cache_clear()
    from app.api.app import create_app

    yield TestClient(create_app())
    for getter in (get_settings, get_repo, get_queue):
        getter.cache_clear()


def _seed(analyzed_at: datetime, value: str, ioc_type: IOCType = IOCType.DOMAIN) -> None:
    from app.api.deps import get_repo

    repo = get_repo()
    if repo.get_case("case0001") is None:
        repo.create_case(Case(id="case0001", title="t", severity=Severity.HIGH))
    repo.save_analysis(
        Analysis(
            case_id="case0001",
            pcap_path="/tmp/x.pcap",
            analyzed_at=analyzed_at,
            iocs=[IOC(ioc_type=ioc_type, value=value, severity=Severity.HIGH)],
        )
    )


def test_stix_pattern_escapes_backslash_before_quote():
    row = {"type": "url", "value": "http://x/a\\b'c"}
    assert _row_to_stix_pattern(row) == "[url:value = 'http://x/a\\\\b\\'c']"


def test_stix_pattern_value_ending_in_backslash_cannot_close_the_literal():
    # Unescaped, the trailing backslash would escape the closing quote and let
    # the rest of an attacker-chosen value extend the pattern.
    pattern = _row_to_stix_pattern({"type": "domain", "value": "evil.example\\"})
    assert pattern == "[domain-name:value = 'evil.example\\\\']"
    inner = pattern[len("[domain-name:value = '") : -len("']")]
    assert inner.count("\\") % 2 == 0


def test_stix_pattern_plain_values_are_unchanged():
    assert _row_to_stix_pattern({"type": "ip", "value": "1.2.3.4"}) == "[ipv4-addr:value = '1.2.3.4']"
    assert _row_to_stix_pattern({"type": "ja3", "value": "x"}) is None


def test_stix_timestamps_are_utc_z_for_aware_and_legacy_naive_rows():
    assert _stix_timestamp("2026-08-01T10:00:00.123456+08:00") == "2026-08-01T02:00:00.123Z"
    assert _stix_timestamp("2026-08-01T02:00:00Z") == "2026-08-01T02:00:00.000Z"
    # Legacy rows were written by naive datetime.now(): local time.
    local = datetime(2026, 8, 1, 10, 0, 0)
    expected = local.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert _stix_timestamp(local.isoformat()) == expected
    assert _stix_timestamp(None) == "1970-01-01T00:00:00.000Z"
    assert _stix_timestamp("garbage") == "1970-01-01T00:00:00.000Z"


def test_stix_bundle_timestamps_and_modified_not_before_created():
    bundle = _to_stix_bundle(
        [
            {
                "type": "ip",
                "value": "1.2.3.4",
                # Text order disagrees with time order across the two stored forms.
                "first_seen": "2026-08-01T09:00:00+00:00",
                "last_seen": "2026-08-01T08:00:00+00:00",
            }
        ]
    )
    indicator = bundle["objects"][0]
    for field in ("created", "modified", "valid_from"):
        assert indicator[field].endswith("Z") and len(indicator[field]) == 24
    assert indicator["modified"] >= indicator["created"]


def test_stix_endpoint_emits_normalised_timestamps(client):
    _seed(datetime(2026, 4, 27, 12, 0, tzinfo=timezone(timedelta(hours=8))), "evil.example")

    response = client.get("/api/v1/iocs.stix", headers=FEED)

    assert response.status_code == 200
    indicator = response.json()["objects"][0]
    assert indicator["created"] == indicator["valid_from"] == "2026-04-27T04:00:00.000Z"


@pytest.mark.parametrize("path", ["/api/v1/iocs.json", "/api/v1/iocs.csv", "/api/v1/iocs.stix", "/api/v1/iocs/stix"])
@pytest.mark.parametrize("cursor", ["abc", "-1", "1.5", "0x10", "１２"])
def test_non_numeric_cursor_is_rejected_with_422(client, path, cursor):
    response = client.get(path, params={"cursor": cursor}, headers=FEED)
    assert response.status_code == 422
    assert response.json()["code"] == "invalid_cursor"


def test_numeric_cursor_still_pages(client):
    for index in range(3):
        _seed(datetime(2026, 4, 27, 12, index, tzinfo=timezone.utc), f"d{index}.example")

    first = client.get("/api/v1/iocs.json", params={"limit": 2}, headers=FEED).json()
    assert first["next_cursor"] == "2"
    second = client.get("/api/v1/iocs.json", params={"limit": 2, "cursor": first["next_cursor"]}, headers=FEED).json()
    assert {row["value"] for row in first["iocs"]} | {row["value"] for row in second["iocs"]} == {
        "d0.example",
        "d1.example",
        "d2.example",
    }


@pytest.mark.parametrize("since", ["yesterday", "2026-99-99", "12345"])
def test_unparseable_since_is_rejected_with_422(client, since):
    response = client.get("/api/v1/iocs.json", params={"since": since}, headers=FEED)
    assert response.status_code == 422
    assert response.json()["code"] == "invalid_since"


def test_since_compares_instants_across_naive_and_offset_rows(client):
    cutoff = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)
    # Aware row one hour BEFORE the cutoff, written with a +14:00 offset: as
    # text ("2026-08-02T01:00...") it sorts after the cutoff and used to leak in.
    _seed((cutoff - timedelta(hours=1)).astimezone(timezone(timedelta(hours=14))), "before-aware.example")
    # Aware row one hour AFTER the cutoff, written with a -12:00 offset: as
    # text ("2026-08-01T01:00...") it sorts before the cutoff and used to be dropped.
    _seed((cutoff + timedelta(hours=1)).astimezone(timezone(timedelta(hours=-12))), "after-aware.example")
    # Legacy naive rows hold local time.
    _seed((cutoff - timedelta(hours=1)).astimezone().replace(tzinfo=None), "before-legacy.example")
    _seed((cutoff + timedelta(hours=1)).astimezone().replace(tzinfo=None), "after-legacy.example")

    # No offset keeps its documented meaning: server-local time.
    local_form = cutoff.astimezone().replace(tzinfo=None).isoformat()
    for since in ("2026-08-01T12:00:00Z", "2026-08-01T20:00:00+08:00", local_form):
        rows = client.get("/api/v1/iocs.json", params={"since": since}, headers=FEED).json()["iocs"]
        assert {row["value"] for row in rows} == {"after-aware.example", "after-legacy.example"}, since


def test_query_iocs_rejects_a_bad_since_instead_of_ignoring_it(client):
    from app.api.deps import get_repo
    from app.api.feed import IOCFilter, query_iocs

    with pytest.raises(ValueError):
        query_iocs(get_repo(), IOCFilter(since="not-a-date"))
