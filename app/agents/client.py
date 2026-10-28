"""Small REST client for case-scoped agent keys; no UI or filesystem access."""

from __future__ import annotations

import os
import re
from urllib.parse import quote, urlsplit

import httpx


class AgentClient:
    def __init__(self, base_url=None, key=None, *, transport=None):
        base_url = base_url or os.getenv("PCAP_HUNTER_AGENT_URL", "http://127.0.0.1:8000")
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("The local agent client requires a loopback API URL.")
        key = key or os.getenv("PCAP_HUNTER_AGENT_KEY", "")
        if not key.startswith("pha_"):
            raise ValueError("A dedicated case-scoped PCAP Hunter agent key is required.")
        self.http = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": "Bearer " + key},
            timeout=30,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    @staticmethod
    def segment(value):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
            raise ValueError("Invalid resource identifier")
        return quote(value, safe="")

    def request(self, method, path, **kwargs):
        with self.http.stream(method, path, **kwargs) as response:
            chunks, size = [], 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > 1024 * 1024:
                    raise RuntimeError("PCAP Hunter response exceeded the agent limit.")
                chunks.append(chunk)
            import json

            try:
                data = json.loads(b"".join(chunks))
            except ValueError:
                raise RuntimeError("PCAP Hunter did not return a structured result.") from None
            if not response.is_success:
                code = data.get("code") or data.get("detail")
                raise RuntimeError(
                    "PCAP Hunter request denied: " + (code if isinstance(code, str) else str(response.status_code))
                )
            return data

    def close(self):
        self.http.close()
