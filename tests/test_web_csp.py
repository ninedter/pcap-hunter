"""Content-Security-Policy and hardening headers for the local workbench."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.database.repository import CaseRepository
from app.web import app as web_app
from app.web.security import CONTENT_SECURITY_POLICY, LocalWorkbenchMiddleware

EXPECTED_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "
    "form-action 'self'"
)


def _directives(policy: str) -> dict[str, list[str]]:
    return {parts[0]: parts[1:] for parts in (item.split() for item in policy.split(";")) if parts}


def test_policy_is_exactly_the_reviewed_string():
    assert CONTENT_SECURITY_POLICY == EXPECTED_POLICY


def test_policy_blocks_inline_script_eval_remote_origins_and_framing():
    directives = _directives(CONTENT_SECURITY_POLICY)
    assert directives["script-src"] == ["'self'"]
    assert directives["connect-src"] == ["'self'"]
    assert directives["object-src"] == ["'none'"]
    assert directives["frame-ancestors"] == ["'none'"]
    assert directives["base-uri"] == ["'self'"]
    assert directives["form-action"] == ["'self'"]
    everything = " ".join(source for sources in directives.values() for source in sources)
    assert "unsafe-eval" not in everything
    assert "*" not in everything and "http" not in everything
    assert "blob:" not in everything and "data:" not in everything
    # The only allowance beyond same-origin is inline styles.
    assert [name for name, sources in directives.items() if "'unsafe-inline'" in sources] == ["style-src"]
    assert {source for sources in directives.values() for source in sources} == {"'self'", "'none'", "'unsafe-inline'"}


@pytest.fixture
def workbench(tmp_path, monkeypatch):
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text(
        '<!doctype html><html><head><script type="module" src="/assets/index.js"></script></head>'
        '<body><div id="root"></div></body></html>'
    )
    (static / "assets" / "index.js").write_text("console.log('ok')")
    monkeypatch.setattr(web_app, "STATIC_DIR", static)
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    monkeypatch.setattr(web_app, "get_repo", lambda: repo)

    from app.utils.config_manager import ConfigManager

    monkeypatch.delenv("PCAP_HUNTER_CONFIG_KEY", raising=False)
    monkeypatch.delenv("PCAP_HUNTER_CONFIG_KEY_FILE", raising=False)
    manager = ConfigManager(tmp_path / "settings.json")
    monkeypatch.setattr(web_app, "get_config_manager", lambda: manager)
    monkeypatch.setattr("app.web.state.get_config_manager", lambda: manager)
    return TestClient(web_app.create_app(), base_url="http://localhost"), repo


@pytest.mark.parametrize("path", ["/", "/dashboard", "/assets/index.js", "/healthz"])
def test_html_shell_assets_and_spa_routes_carry_the_policy(workbench, path):
    client, _ = workbench
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-security-policy"] == EXPECTED_POLICY
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "same-origin"


@pytest.mark.parametrize("path", ["/api/ui/bootstrap", "/api/ui/settings", "/api/ui/jobs", "/api/ui/cases/missing"])
def test_api_responses_carry_the_policy_including_errors(workbench, path):
    client, _ = workbench
    response = client.get(path)
    assert response.status_code in {200, 404}
    assert response.headers["content-security-policy"] == EXPECTED_POLICY
    assert response.headers["cache-control"] == "no-store"


def test_pdf_download_still_works_under_the_policy(workbench, tmp_path, monkeypatch):
    """The real report route: a cached PDF is served as an attachment with the policy attached."""
    from app.database.models import Case

    client, repo = workbench
    repo.create_case(Case(id="pdfcase", title="t"))
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "pdfcase.pdf").write_bytes(b"%PDF-1.7 cached")
    monkeypatch.setenv("PCAP_HUNTER_REPORTS_DIR", str(reports))
    monkeypatch.delenv("PCAP_HUNTER_API_REPORTS_DIR", raising=False)

    response = client.get("/api/ui/cases/pdfcase/report.pdf")

    assert response.status_code == 200
    assert response.content == b"%PDF-1.7 cached"
    assert response.headers["content-type"] == "application/pdf"
    # An attachment is downloaded, never rendered in this origin, so no directive can break it.
    assert response.headers["content-disposition"].startswith("attachment")
    assert response.headers["content-security-policy"] == EXPECTED_POLICY


def test_requests_rejected_by_the_boundary_are_hardened_too():
    app = FastAPI()
    app.add_middleware(LocalWorkbenchMiddleware)

    @app.api_route("/api/ui/probe", methods=["GET", "POST"])
    def probe():
        return {"ok": True}

    client = TestClient(app, base_url="http://127.0.0.1:8501")
    rejected = [
        client.get("/api/ui/probe", headers={"Host": "attacker.example"}),
        client.get("/api/ui/probe", headers={"Origin": "https://attacker.example"}),
        client.post("/api/ui/probe", content="a=b", headers={"Content-Type": "text/plain"}),
        client.post("/api/ui/probe", content=b"x" * 70000, headers={"Content-Type": "application/json"}),
    ]
    assert [response.status_code for response in rejected] == [400, 403, 415, 413]
    for response in rejected:
        assert response.headers["content-security-policy"] == EXPECTED_POLICY
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["cache-control"] == "no-store"


_REPO_ROOT = Path(__file__).resolve().parent.parent
_BUILT_SHELLS = [
    path
    for path in (
        _REPO_ROOT / "app" / "web" / "static" / "index.html",
        _REPO_ROOT / "prototype-friendly-ui" / "dist" / "client" / "index.html",
    )
    if path.is_file()
]


@pytest.mark.skipif(not _BUILT_SHELLS, reason="React client has not been built on this machine")
@pytest.mark.parametrize("shell", _BUILT_SHELLS, ids=lambda path: path.parent.parent.name)
def test_built_shell_needs_nothing_the_policy_forbids(shell):
    """Guards the build output: an inline script or a remote asset would be blocked in the browser."""
    html = shell.read_text(encoding="utf-8")
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", html, flags=re.S | re.I)
    assert scripts, "expected the module entry point"
    for attributes, body in scripts:
        assert "src=" in attributes and not body.strip(), "inline <script> would be blocked by script-src 'self'"
    for url in re.findall(r"""(?:src|href)=["']([^"']+)["']""", html):
        assert url.startswith("/") and not url.startswith("//"), f"non same-origin asset: {url}"
    assert not re.search(r"\son[a-z]+\s*=", html), "inline event handlers would be blocked"
