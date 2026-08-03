from datetime import datetime

from fastapi.responses import Response
from fastapi.testclient import TestClient

from app.database.repository import CaseRepository
from app.web import app as web_app


def _client(monkeypatch, tmp_path) -> TestClient:
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    monkeypatch.setattr(web_app, "get_repo", lambda: repo)
    return TestClient(web_app.create_app())


def test_geo_picker_resolves_taipei_coordinates(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)

    assert "Asia" in client.get("/api/ui/geo/continents").json()["items"]
    assert "Taiwan" in client.get("/api/ui/geo/countries", params={"continent": "Asia"}).json()["items"]
    assert "Taipei" in client.get("/api/ui/geo/cities", params={"country": "Taiwan"}).json()["items"]

    location = client.get("/api/ui/geo/location", params={"country": "Taiwan", "city": "Taipei"})
    assert location.status_code == 200
    assert 24 < location.json()["latitude"] < 26
    assert 120 < location.json()["longitude"] < 122


def test_local_pdf_route_uses_shared_report_generator(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(
        web_app,
        "build_case_report_response",
        lambda case_id, repo: Response(b"%PDF-test", media_type="application/pdf"),
    )

    response = client.get("/api/ui/cases/case-001/report.pdf")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF")


def test_whois_route_returns_json_safe_domain_record(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(
        web_app,
        "get_whois_info",
        lambda target: {"domain_name": target, "creation_date": datetime(1995, 8, 14), "name_servers": {"A", "B"}},
    )

    response = client.get("/api/ui/whois", params={"target": "Example.com."})

    assert response.status_code == 200
    assert response.json()["target"] == "example.com"
    assert response.json()["record"]["creation_date"] == "1995-08-14T00:00:00"
    assert sorted(response.json()["record"]["name_servers"]) == ["A", "B"]


def test_whois_route_rejects_private_ip_without_lookup(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)

    def lookup(target):
        raise AssertionError("lookup should not run")

    monkeypatch.setattr(web_app, "get_whois_info", lookup)

    response = client.get("/api/ui/whois", params={"target": "192.168.1.10"})

    assert response.status_code == 422
