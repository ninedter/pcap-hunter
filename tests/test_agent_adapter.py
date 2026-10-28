"""The official MCP SDK exposes only granted tools and structured evidence."""

import asyncio

import httpx
import pytest
from mcp import Client

from app.agents.client import AgentClient
from app.agents.mcp import create_server


class MockAPI:
    segment = staticmethod(AgentClient.segment)

    def __init__(self, permissions):
        self.permissions = permissions
        self.calls = []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if path.endswith("/capabilities"):
            return {"permissions": self.permissions, "case_ids": ["case-a"]}
        return {
            "items": [{"id": "record-a", "value": "example.invalid"}],
            "coverage": {"packet_parse": "partial"},
            "next_cursor": None,
        }


def test_mcp_uses_sdk_and_never_exposes_writes_to_a_reader():
    api = MockAPI(["cases:read", "evidence:read", "jobs:read"])
    server = create_server(api)

    async def check():
        async with Client(server) as client:
            tools = await client.list_tools()
            names = {tool.name for tool in tools.tools}
            assert {"query_evidence", "get_evidence", "list_cases"} <= names
            assert not {"submit_capture", "append_investigation_draft", "cancel_job", "delete_case", "settings"} & names
            result = await client.call_tool("query_evidence", {"analysis_id": "analysis-a", "limit": 50})
            assert not result.is_error
            assert result.structured_content["coverage"]["packet_parse"] == "partial"

    asyncio.run(check())
    assert api.calls[-1][2]["params"] == {"limit": 50}


def test_mcp_has_controlled_writes_only_when_granted():
    server = create_server(MockAPI(["captures:submit", "notes:append"]))

    async def check():
        async with Client(server) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            assert names == {"submit_capture", "cancel_job", "append_investigation_draft"}

    asyncio.run(check())


@pytest.mark.parametrize(
    "url", ["https://attacker.invalid", "http://169.254.169.254", "http://user@localhost", "http://localhost/api"]
)
def test_local_client_cannot_be_redirected_to_an_external_or_credential_url(url):
    with pytest.raises(ValueError):
        AgentClient(url, "pha_dummy")


@pytest.mark.parametrize("value", ["../admin", "a/b", "a?query", "a%2fb"])
def test_client_resource_names_cannot_select_other_routes(value):
    with pytest.raises(ValueError):
        AgentClient.segment(value)


def test_client_does_not_follow_redirects_or_send_keys_to_another_destination():
    calls = []

    def redirect(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://attacker.invalid"}, json={"detail": "redirect_denied"})

    client = AgentClient(key="pha_dummy", transport=httpx.MockTransport(redirect))
    with pytest.raises(RuntimeError, match="redirect_denied"):
        client.request("GET", "/api/v1/agent/capabilities")
    client.close()
    assert calls == ["http://127.0.0.1:8000/api/v1/agent/capabilities"]
