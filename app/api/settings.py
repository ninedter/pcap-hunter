"""API settings loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


class NoKeysConfiguredError(RuntimeError):
    """Raised when no auth keys exist (neither env vars nor DB keys)."""


FULL_SCOPE_RECOVERY_HINT = (
    "Recover by setting PCAP_HUNTER_API_KEY and restarting, "
    "or by creating a full-scope key in the Streamlit 'API Keys' tab."
)


@dataclass(frozen=True)
class APISettings:
    main_key: str | None
    feed_key: str | None
    host: str
    port: int
    workers: int
    queue_depth: int
    max_pcap_bytes: int
    upload_timeout_seconds: int
    pcap_ttl_days: int
    artifact_ttl_days: int
    job_ttl_days: int
    require_https: bool
    cors_origins: list[str]

    @classmethod
    def from_env(cls) -> "APISettings":
        main = os.environ.get("PCAP_HUNTER_API_KEY") or None
        feed = os.environ.get("PCAP_HUNTER_FEED_KEY") or None
        # Env-var keys are optional when DB-backed keys exist.
        # The app checks for at least one auth source at startup.

        cpu = max(1, (os.cpu_count() or 2) // 2)
        return cls(
            main_key=main,
            feed_key=feed,
            host=os.environ.get("PCAP_HUNTER_API_HOST", "127.0.0.1"),
            port=int(os.environ.get("PCAP_HUNTER_API_PORT", "8000")),
            workers=int(os.environ.get("PCAP_HUNTER_API_WORKERS", str(cpu))),
            queue_depth=int(os.environ.get("PCAP_HUNTER_API_QUEUE_DEPTH", "100")),
            max_pcap_bytes=int(os.environ.get("PCAP_HUNTER_API_MAX_PCAP_BYTES", str(2 * 1024**3))),
            upload_timeout_seconds=int(os.environ.get("PCAP_HUNTER_API_UPLOAD_TIMEOUT_SEC", "600")),
            pcap_ttl_days=int(os.environ.get("PCAP_HUNTER_API_PCAP_TTL_DAYS", "7")),
            artifact_ttl_days=int(os.environ.get("PCAP_HUNTER_API_ARTIFACT_TTL_DAYS", "30")),
            job_ttl_days=int(os.environ.get("PCAP_HUNTER_API_JOB_TTL_DAYS", "30")),
            require_https=os.environ.get("PCAP_HUNTER_API_REQUIRE_HTTPS", "false").lower() == "true",
            cors_origins=[
                o.strip() for o in os.environ.get("PCAP_HUNTER_API_CORS_ORIGINS", "").split(",") if o.strip()
            ],
        )
