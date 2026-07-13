# tests/api/test_iocs.py
"""Tests for GET /api/v1/iocs.{json,csv,stix} feed endpoints."""

from __future__ import annotations

from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from app.database.models import IOC, Analysis, Case, IOCType, Severity


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_FEED_KEY", "FEED")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))

    from app.api.deps import get_queue, get_repo, get_settings

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()

    from app.api.app import create_app
    from app.api.deps import get_repo as _get_repo

    repo = _get_repo()
    case = Case(id="case0001", title="t", severity=Severity.HIGH)
    repo.create_case(case)
    analysis = Analysis(
        case_id=case.id,
        pcap_path="/tmp/x.pcap",
        analyzed_at=datetime(2026, 4, 27, 12, 0),
        iocs=[IOC(ioc_type=IOCType.IP, value="1.2.3.4", severity=Severity.HIGH)],
    )
    repo.save_analysis(analysis)

    yield TestClient(create_app())

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()


def test_iocs_json_with_feed_key(client):
    r = client.get("/api/v1/iocs.json", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    assert any(i["value"] == "1.2.3.4" for i in body["iocs"])


def test_iocs_json_with_main_key_also_works(client):
    r = client.get("/api/v1/iocs.json", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 200


def test_iocs_json_unauthenticated_401(client):
    r = client.get("/api/v1/iocs.json")
    assert r.status_code == 401


def test_iocs_json_filter_by_type(client):
    r = client.get("/api/v1/iocs.json?type=ip", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    assert all(i["type"] == "ip" for i in r.json()["iocs"])


# ── ETag / 304 ──────────────────────────────────────────────────────────────


def test_etag_round_trip(client):
    r1 = client.get("/api/v1/iocs.json", headers={"Authorization": "Bearer FEED"})
    assert r1.status_code == 200
    etag = r1.headers["ETag"]

    r2 = client.get(
        "/api/v1/iocs.json",
        headers={"Authorization": "Bearer FEED", "If-None-Match": etag},
    )
    assert r2.status_code == 304
    assert r2.content == b""


# ── CSV feed ────────────────────────────────────────────────────────────────


def test_iocs_csv(client):
    r = client.get("/api/v1/iocs.csv", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    text = r.text
    # Header row
    assert text.splitlines()[0] == "type,value,score,severity,tags,first_seen,last_seen,case_ids,mitre_techniques"
    # Body row
    assert "1.2.3.4" in text


def test_csv_injection_safe(client):
    """A value starting with =, +, -, @ must be prefixed to neutralize."""
    from app.api.deps import get_repo

    repo = get_repo()
    case = Case(id="case0002", title="evil")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            case_id=case.id,
            pcap_path="/tmp/y.pcap",
            iocs=[IOC(ioc_type=IOCType.URL, value="=cmd|'/c calc'!A1")],
        )
    )

    r = client.get("/api/v1/iocs.csv", headers={"Authorization": "Bearer FEED"})
    # The raw dangerous value must NOT appear as a field start; it must be prefixed
    lines = r.text.strip().splitlines()
    for line in lines[1:]:  # skip header
        for field in line.split(","):
            stripped = field.strip().strip('"')
            assert not stripped.startswith("="), f"CSV injection: field starts with '=' -> {stripped}"
    # Confirm the prefix is present
    assert "'=cmd" in r.text


# ── STIX 2.1 feed ──────────────────────────────────────────────────────────


def test_iocs_stix_bundle(client):
    r = client.get("/api/v1/iocs.stix", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "bundle"
    assert body["spec_version"] == "2.1"
    objs = body.get("objects", [])
    assert any(o.get("type") == "indicator" for o in objs)


def test_iocs_stix_md5_hash_type(client):
    """An MD5-length hash IOC must emit file:hashes.MD5, not the hardcoded SHA-256."""
    from app.api.deps import get_repo

    md5_value = "c0" * 16  # 32 hex chars -> MD5
    repo = get_repo()
    case = Case(id="case0005", title="md5")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            case_id=case.id,
            pcap_path="/tmp/md5.pcap",
            iocs=[IOC(ioc_type=IOCType.HASH, value=md5_value)],
        )
    )

    r = client.get("/api/v1/iocs.stix", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    body = r.json()
    matching = [o["pattern"] for o in body["objects"] if o.get("type") == "indicator" and md5_value in o["pattern"]]
    assert matching, "expected an indicator pattern for the MD5 IOC"
    assert "file:hashes.MD5" in matching[0]
    assert "SHA-256" not in matching[0]


def test_iocs_stix_ja3_not_dropped(client):
    """JA3 rows must be emitted, not silently dropped."""
    from app.api.deps import get_repo

    ja3_value = "e" * 32
    repo = get_repo()
    case = Case(id="case0006", title="ja3")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            case_id=case.id,
            pcap_path="/tmp/ja3.pcap",
            iocs=[IOC(ioc_type=IOCType.JA3, value=ja3_value)],
        )
    )

    r = client.get("/api/v1/iocs.stix", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    body = r.json()
    matching = [o["pattern"] for o in body["objects"] if o.get("type") == "indicator" and ja3_value in o["pattern"]]
    assert matching, "expected a JA3 indicator pattern, but it was dropped"
    assert "x509-certificate" in matching[0]


# ── Pagination ──────────────────────────────────────────────────────────────


def test_iocs_pagination(client):
    """Seed >2 IOCs, request limit=1, follow next_cursor."""
    from app.api.deps import get_repo

    repo = get_repo()
    case = Case(id="case0003", title="paging")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            case_id=case.id,
            pcap_path="/tmp/p.pcap",
            iocs=[
                IOC(ioc_type=IOCType.IP, value="10.0.0.1"),
                IOC(ioc_type=IOCType.IP, value="10.0.0.2"),
                IOC(ioc_type=IOCType.IP, value="10.0.0.3"),
            ],
        )
    )

    r1 = client.get("/api/v1/iocs.json?limit=1", headers={"Authorization": "Bearer FEED"})
    body1 = r1.json()
    assert len(body1["iocs"]) == 1
    assert body1["next_cursor"] is not None

    r2 = client.get(
        f"/api/v1/iocs.json?limit=1&cursor={body1['next_cursor']}",
        headers={"Authorization": "Bearer FEED"},
    )
    body2 = r2.json()
    assert len(body2["iocs"]) == 1
    assert body1["iocs"][0]["value"] != body2["iocs"][0]["value"]


# ── _http_date unit test ────────────────────────────────────────────────────


def test_http_date_treats_naive_as_local():
    from datetime import datetime, timezone
    from email.utils import parsedate_to_datetime

    from app.api.routers.iocs import _http_date

    naive = datetime(2026, 6, 11, 13, 12, 46)
    out = _http_date(naive.isoformat())
    expected = naive.astimezone(timezone.utc)  # local -> utc
    assert parsedate_to_datetime(out) == expected


# ── Last-Modified (RFC 7231) ────────────────────────────────────────────────


def test_last_modified_is_rfc7231(client):
    from email.utils import parsedate_to_datetime

    from app.api.deps import get_repo

    repo = get_repo()
    case = Case(id="case0004", title="lastmod")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            case_id=case.id,
            pcap_path="/tmp/lm.pcap",
            analyzed_at=datetime(2026, 6, 11, 13, 12, 46),
            iocs=[IOC(ioc_type=IOCType.IP, value="203.0.113.7", severity=Severity.HIGH)],
        )
    )

    r = client.get("/api/v1/iocs.json", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 200
    lm = r.headers.get("last-modified")
    assert lm and lm.endswith("GMT")
    assert parsedate_to_datetime(lm) is not None
