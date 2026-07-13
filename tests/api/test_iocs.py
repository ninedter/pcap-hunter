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


# ── mitre_techniques derivation ─────────────────────────────────────────────


def test_iocs_json_includes_mitre_techniques(client):
    """mitre_techniques must be derived from the analysis, not the hardcoded []."""
    from app.api.deps import get_repo

    repo = get_repo()
    case = Case(id="case0007", title="mitre")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            case_id=case.id,
            pcap_path="/tmp/m.pcap",
            mitre_techniques=["T1071.001"],
            iocs=[IOC(ioc_type=IOCType.IP, value="9.9.9.9", severity=Severity.HIGH)],
        )
    )

    r = client.get("/api/v1/iocs.json", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    row = next(i for i in r.json()["iocs"] if i["value"] == "9.9.9.9")
    assert row["mitre_techniques"] == ["T1071.001"]


def test_iocs_json_multi_technique_multi_tag_no_tag_duplication(client):
    """Fan-out guard at the API layer: multiple techniques + multiple tags on the
    same IOC's analysis must not duplicate tags or technique IDs in the response."""
    from app.api.deps import get_repo

    repo = get_repo()
    case = Case(id="case0008", title="multi", tags=["tag-x", "tag-y"])
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            case_id=case.id,
            pcap_path="/tmp/m2.pcap",
            mitre_techniques=["T1059", "T1071.001"],
            iocs=[IOC(ioc_type=IOCType.IP, value="7.7.7.7", severity=Severity.HIGH)],
        )
    )

    r = client.get("/api/v1/iocs.json", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    row = next(i for i in r.json()["iocs"] if i["value"] == "7.7.7.7")
    assert sorted(row["mitre_techniques"]) == ["T1059", "T1071.001"]
    assert sorted(row["tags"]) == ["tag-x", "tag-y"]


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


# ── CEF feed ────────────────────────────────────────────────────────────────


def test_iocs_cef_low_ioc_not_dropped(client):
    """A LOW-severity IOC (score 25) must appear in CEF output.

    The generic priority-score gate in cef_export._events_from_iocs drops
    anything below 0.4 — a naive `score/100` mapping would silently drop a
    LOW (25 -> 0.25) IOC from a feed pull. The dedicated feed adapter must
    not apply that gate at all.
    """
    from app.api.deps import get_repo

    repo = get_repo()
    case = Case(id="case0010", title="cef-low")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            case_id=case.id,
            pcap_path="/tmp/low.pcap",
            iocs=[IOC(ioc_type=IOCType.IP, value="66.66.66.66", severity=Severity.LOW)],
        )
    )

    r = client.get("/api/v1/iocs.cef", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert "CEF:0" in r.text
    # The seeded HIGH IOC (fixture) and the new LOW IOC must BOTH appear.
    assert "1.2.3.4" in r.text
    assert "66.66.66.66" in r.text


def test_iocs_cef_respects_min_score(client):
    from app.api.deps import get_repo

    repo = get_repo()
    case = Case(id="case0011", title="cef-minscore")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            case_id=case.id,
            pcap_path="/tmp/lo2.pcap",
            iocs=[IOC(ioc_type=IOCType.IP, value="77.77.77.77", severity=Severity.LOW)],
        )
    )

    r = client.get("/api/v1/iocs.cef?min_score=50", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    assert "77.77.77.77" not in r.text  # LOW (25) filtered out by min_score=50
    assert "1.2.3.4" in r.text  # HIGH (75) survives the >=50 filter


def test_iocs_cef_requires_feed_scope(client):
    r = client.get("/api/v1/iocs.cef")
    assert r.status_code == 401


def test_iocs_cef_escaping_safe(client):
    """CEF reserved characters (=, \\) in a value must be escaped, not raw."""
    from app.api.deps import get_repo

    repo = get_repo()
    case = Case(id="case0013", title="cef-escape")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            case_id=case.id,
            pcap_path="/tmp/esc.pcap",
            iocs=[IOC(ioc_type=IOCType.URL, value="http://evil.example/a=b")],
        )
    )

    r = client.get("/api/v1/iocs.cef", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    assert "a\\=b" in r.text
    assert "a=b" not in r.text.replace("a\\=b", "")


def test_iocs_cef_etag_round_trip(client):
    r1 = client.get("/api/v1/iocs.cef", headers={"Authorization": "Bearer FEED"})
    assert r1.status_code == 200
    etag = r1.headers["ETag"]

    r2 = client.get(
        "/api/v1/iocs.cef",
        headers={"Authorization": "Bearer FEED", "If-None-Match": etag},
    )
    assert r2.status_code == 304
    assert r2.content == b""


# ── Single-IOC lookup ───────────────────────────────────────────────────────


def test_iocs_lookup_exact_match(client):
    r = client.get("/api/v1/iocs/lookup?value=1.2.3.4", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    assert body["next_cursor"] is None
    assert len(body["iocs"]) == 1
    entry = body["iocs"][0]
    assert entry["value"] == "1.2.3.4"
    assert entry["type"] == "ip"
    assert entry["score"] == 75
    assert entry["severity"] == "high"


def test_iocs_lookup_unknown_value_returns_empty(client):
    r = client.get("/api/v1/iocs/lookup?value=nonexistent.example", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    assert r.json() == {"iocs": [], "count": 0, "next_cursor": None}


def test_iocs_lookup_requires_feed_scope(client):
    r = client.get("/api/v1/iocs/lookup?value=1.2.3.4")
    assert r.status_code == 401


def test_iocs_lookup_missing_value_param_422(client):
    r = client.get("/api/v1/iocs/lookup", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 422


def test_iocs_lookup_empty_value_422_not_whole_feed(client):
    # An empty value must be rejected, never silently dump the entire feed.
    r = client.get("/api/v1/iocs/lookup?value=", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 422


def test_iocs_lookup_exact_not_substring(client):
    """value=1.2.3.4 must not also return 1.2.3.40."""
    from app.api.deps import get_repo

    repo = get_repo()
    case = Case(id="case0009", title="substring")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            case_id=case.id,
            pcap_path="/tmp/sub.pcap",
            iocs=[IOC(ioc_type=IOCType.IP, value="1.2.3.40", severity=Severity.LOW)],
        )
    )

    r = client.get("/api/v1/iocs/lookup?value=1.2.3.4", headers={"Authorization": "Bearer FEED"})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    assert body["iocs"][0]["value"] == "1.2.3.4"


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
