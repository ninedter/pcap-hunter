"""The local browser API must not accept actions from another website."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.web.security import LocalWorkbenchMiddleware


@pytest.fixture
def guarded_client():
    app = FastAPI()
    app.add_middleware(LocalWorkbenchMiddleware)
    calls = []

    @app.api_route("/api/ui/probe", methods=["GET", "POST", "PUT"])
    @app.post("/api/ui/uploads")
    def probe():
        calls.append(True)
        return {"ok": True}

    return TestClient(app, base_url="http://127.0.0.1:8501"), calls


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]"])
def test_loopback_hosts_are_accepted(guarded_client, host):
    client, calls = guarded_client
    assert client.get("/api/ui/probe", headers={"Host": f"{host}:8501"}).status_code == 200
    assert calls == [True]


@pytest.mark.parametrize("host", ["attacker.example", "127.0.0.1.attacker.example", "192.168.1.2", "[broken"])
def test_other_hosts_never_reach_handler(guarded_client, host):
    client, calls = guarded_client
    assert client.get("/api/ui/probe", headers={"Host": host}).status_code == 400
    assert calls == []


@pytest.mark.parametrize("method", ["GET", "POST", "PUT"])
@pytest.mark.parametrize("origin", ["https://attacker.example", "null", "http://127.0.0.1:8502"])
def test_cross_origin_requests_never_reach_handler(guarded_client, method, origin):
    client, calls = guarded_client
    response = client.request(method, "/api/ui/probe", headers={"Origin": origin}, json={})
    assert response.status_code == 403
    assert calls == []


@pytest.mark.parametrize("fetch_site", ["cross-site", "same-site"])
def test_fetch_metadata_blocks_calls_even_without_origin(guarded_client, fetch_site):
    client, calls = guarded_client
    response = client.post("/api/ui/probe", headers={"Sec-Fetch-Site": fetch_site}, json={})
    assert response.status_code == 403
    assert calls == []


def test_simple_text_form_cannot_create_records(guarded_client):
    client, calls = guarded_client
    response = client.post("/api/ui/probe", content='{"title":"probe"}', headers={"Content-Type": "text/plain"})
    assert response.status_code == 415
    assert calls == []


def test_same_origin_json_and_uploads_work(guarded_client):
    client, calls = guarded_client
    headers = {"Origin": "http://127.0.0.1:8501", "Sec-Fetch-Site": "same-origin"}
    response = client.post("/api/ui/probe", json={}, headers=headers)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-frame-options"] == "DENY"
    assert client.post("/api/ui/uploads", files={"files": ("probe.pcap", b"test")}, headers=headers).status_code == 200
    assert calls == [True, True]
