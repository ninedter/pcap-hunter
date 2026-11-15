"""Production PCAP Hunter web workbench.

The React shell is served from the same local-only process as its UI API so the
approved prototype can become the real product without browser-side API keys.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import os
import pathlib
import re
import threading
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, nullcontext
from datetime import date, datetime
from itertools import islice
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from app import config as C
from app.api.deps import get_queue, get_repo, get_settings
from app.api.queue import (
    LMSTUDIO_PLACEHOLDER_KEY,
    OPENAI_DEFAULT_BASE_URL,
    JobSubmission,
    QueueFullError,
    default_llm_base_url,
    job_sweep_loop,
    recover_jobs_at_boot,
    resolve_llm_api_key,
    url_origin,
)
from app.api.routers.cases import build_case_report_response
from app.api.validation import is_valid_pcap_magic
from app.database.models import Case, CaseStatus, Severity
from app.utils.config_manager import SENSITIVE_KEYS, get_config_manager
from app.utils.geo_data import get_cities, get_continents, get_countries, get_location_details
from app.utils.network_utils import _validate_domain, get_whois_info, is_public_ipv4
from app.web.agent_routes import router as local_agent_router
from app.web.security import LocalWorkbenchMiddleware
from app.web.state import build_workbench_state, public_config, serialize_jobs

logger = logging.getLogger(__name__)

STATIC_DIR = pathlib.Path(__file__).with_name("static")
UPLOADS_DIR_DEFAULT = pathlib.Path("data/api_uploads")
CONFIG_KEYS = {
    "cfg_llm_endpoint",
    "cfg_llm_model",
    "cfg_llm_language",
    "cfg_llm_provider",
    "cfg_llm_context_window",
    "cfg_llm_unlimited_context",
    "cfg_openai_model",
    "cfg_openai_base_url",
    "cfg_anthropic_model",
    "cfg_pyshark_limit",
    "cfg_osint_top_ips",
    "cfg_osint_cache_enabled",
    "cfg_yara_rules_dir",
    "cfg_zeek_bin",
    "cfg_tshark_bin",
    "cfg_home_lat",
    "cfg_home_lon",
    "cfg_home_continent",
    "cfg_home_country",
    "cfg_home_city",
    *SENSITIVE_KEYS,
}

_LLM_PROVIDERS = {"lmstudio", "openai", "anthropic"}
_LLM_PROVIDER_LABELS = {
    "lmstudio": "LM Studio",
    "openai": "OpenAI",
    "anthropic": "Anthropic",
}
_LLM_MODEL_LIMIT = 100


def _draft_value(payload: dict[str, Any], key: str, saved_value: Any) -> str:
    """Use a non-empty browser draft, otherwise the saved value.

    Connection checks must be useful before users save settings.  Draft values
    are deliberately kept request-local and never passed to the config manager.
    """
    if key in payload and payload[key] is not None:
        if not isinstance(payload[key], str):
            raise HTTPException(status_code=422, detail=f"{key}_must_be_a_string")
        value = payload[key].strip()
        if value:
            return value
    return str(saved_value or "").strip()


def _model_ids(response: Any) -> list[str]:
    """Extract a bounded, stable list of model IDs from either provider SDK."""
    items = getattr(response, "data", response)
    ids: set[str] = set()
    for item in islice(items, _LLM_MODEL_LIMIT):
        value = item if isinstance(item, str) else getattr(item, "id", "")
        model_id = str(value).strip()
        if model_id:
            ids.add(model_id)
    return sorted(ids)[:_LLM_MODEL_LIMIT]


_NUMERIC_HOST_PART = re.compile(r"0[xX][0-9a-fA-F]*|[0-9]*")


def _validated_model_base_url(value: str) -> str:
    """Accept only normal HTTP(S) API URLs before an SDK opens a connection.

    Loopback and private addresses stay allowed (LM Studio on localhost, a LAN host or
    ``host.docker.internal``). Link-local (cloud metadata), unspecified and multicast
    addresses are refused, including when written as an IPv4-mapped IPv6 literal or in
    a non-canonical numeric form.
    """
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid_model_api_url") from exc
    hostname = parsed.hostname or ""
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or not hostname
        or hostname != hostname.strip()
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        and not 1 <= port <= 65535
    ):
        raise HTTPException(status_code=422, detail="invalid_model_api_url")
    if parsed.query or parsed.fragment:
        raise HTTPException(status_code=422, detail="invalid_model_api_url")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        # Not a canonical IP literal. Resolvers still read bare integers, hex/octal parts
        # and short dotted forms as IPv4 (``2852039166``, ``0xa9fea9fe``, ``169.254.43518``),
        # which would slip past the address checks below, so a host made only of numeric
        # parts must be a canonical dotted quad. No DNS resolution is performed.
        parts = hostname.rstrip(".").split(".")
        if all(_NUMERIC_HOST_PART.fullmatch(part) for part in parts):
            raise HTTPException(status_code=422, detail="invalid_model_api_url") from None
    else:
        # ``::ffff:169.254.169.254`` reaches the IPv4 address it wraps.
        address = getattr(address, "ipv4_mapped", None) or address
        if address.is_link_local or address.is_unspecified or address.is_multicast:
            raise HTTPException(status_code=422, detail="invalid_model_api_url")
    return value


def _destination_key(payload, saved_key, base_url, saved_url):
    explicit = _draft_value(payload, "api_key", "")
    if explicit:
        return explicit
    # A stored key belongs only to its saved destination, never a new draft URL.
    return str(saved_key or "") if base_url.rstrip("/") == saved_url.rstrip("/") else ""


# ---- Settings validation -------------------------------------------------

_SETTINGS_TEXT_MAX = 2048
_INT_SETTINGS: dict[str, tuple[int, int]] = {
    "cfg_pyshark_limit": (0, 1_000_000_000),
    "cfg_osint_top_ips": (0, 1000),
    "cfg_llm_context_window": (C.LLM_CONTEXT_WINDOW_MIN, C.LLM_CONTEXT_WINDOW_MAX),
}
_FLOAT_SETTINGS: dict[str, tuple[float, float]] = {
    "cfg_home_lat": (-90.0, 90.0),
    "cfg_home_lon": (-180.0, 180.0),
}
_BOOL_SETTINGS = {"cfg_llm_unlimited_context", "cfg_osint_cache_enabled"}
# Provider base URL -> the stored credential that is only valid for that host.
_BASE_URL_SECRETS = {
    "cfg_openai_base_url": "cfg_openai_cloud_key",
    "cfg_llm_endpoint": "cfg_openai_key",
}
_OPENAI_DEFAULT_BASE_URL = OPENAI_DEFAULT_BASE_URL
# In-process guard for load-mutate-save; the config manager's own file lock
# (re-entrant, cross-process) is taken as well when it is available.
_SETTINGS_LOCK = threading.Lock()


class _SettingError(ValueError):
    """A single rejected settings field (message is safe to show the user)."""


def _coerce_setting(key: str, value: Any) -> Any:
    """Validate one settings value and return its normalised form.

    Raises:
        _SettingError: With a user-facing message when the value is the wrong
            type or out of range for ``key``.
    """
    if key in _INT_SETTINGS:
        low, high = _INT_SETTINGS[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise _SettingError("must be a whole number")
        if isinstance(value, float) and (not math.isfinite(value) or value != int(value)):
            raise _SettingError("must be a whole number")
        number = int(value)
        if not low <= number <= high:
            raise _SettingError(f"must be between {low} and {high}")
        return number
    if key in _FLOAT_SETTINGS:
        low, high = _FLOAT_SETTINGS[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise _SettingError("must be a number")
        if not low <= value <= high:
            raise _SettingError(f"must be between {low:g} and {high:g}")
        return float(value)
    if key in _BOOL_SETTINGS:
        if not isinstance(value, bool):
            raise _SettingError("must be true or false")
        return value
    if not isinstance(value, str):
        raise _SettingError("must be text")
    if len(value) > _SETTINGS_TEXT_MAX:
        raise _SettingError(f"must be at most {_SETTINGS_TEXT_MAX} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise _SettingError("must not contain control characters")
    if key == "cfg_llm_provider" and value not in _LLM_PROVIDERS:
        raise _SettingError("must be one of: " + ", ".join(sorted(_LLM_PROVIDERS)))
    if key in _BASE_URL_SECRETS:
        value = value.strip()
        if value:
            try:
                _validated_model_base_url(value)
            except HTTPException as exc:
                raise _SettingError("must be a plain http(s) API URL without credentials, query, or fragment") from exc
    return value


def _effective_base_url(key: str, value: Any) -> str:
    """The URL a worker would actually call for this setting (blank = default)."""
    text = str(value or "").strip()
    if text:
        return text
    return default_llm_base_url("openai" if key == "cfg_openai_base_url" else "lmstudio")


# Shared with the worker, which applies the same origin rule to environment-supplied keys.
_url_origin = url_origin


def _apply_settings_update(current: dict[str, Any], payload: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    """Validate ``payload`` and merge it into ``current`` in place.

    The browser sends its whole settings draft on every save: every non-secret
    value (changed or not) plus a secret only when the analyst typed one.
    Unknown keys are ignored, ``null`` leaves a value unchanged, and a blank
    secret keeps the stored one.

    A stored provider key is bound to the host it was saved for. When a save
    moves a provider's base URL to a different origin without supplying a new
    key in the same request, the stored key is cleared rather than later sent
    to the new host.

    Args:
        current: Stored configuration (mutated only when there are no errors).
        payload: Browser-submitted settings object.

    Returns:
        ``(errors, cleared_keys)`` — per-field messages, and the secrets that
        were cleared because their provider's host changed.
    """
    errors: dict[str, str] = {}
    updates: dict[str, Any] = {}
    for key, value in payload.items():
        if key not in CONFIG_KEYS or value is None:
            continue
        if key in SENSITIVE_KEYS:
            if not isinstance(value, str):
                errors[key] = "must be text"
            elif len(value) > _SETTINGS_TEXT_MAX or any(ord(char) < 32 or ord(char) == 127 for char in value):
                errors[key] = "is not a valid key value"
            elif value.strip():
                updates[key] = value.strip()
            continue
        if value == current.get(key) and type(value) is type(current.get(key)):
            continue  # unchanged echo of the stored value, nothing to validate or bind
        try:
            updates[key] = _coerce_setting(key, value)
        except _SettingError as exc:
            errors[key] = str(exc)
    if errors:
        return errors, []

    cleared: list[str] = []
    for url_key, secret_key in _BASE_URL_SECRETS.items():
        if url_key not in updates or secret_key in updates or not current.get(secret_key):
            continue
        before = _url_origin(_effective_base_url(url_key, current.get(url_key)))
        after = _url_origin(_effective_base_url(url_key, updates[url_key]))
        if before != after:
            updates[secret_key] = ""
            cleared.append(secret_key)
    current.update(updates)
    return {}, cleared


async def _json_object(request: Request, *, detail: str = "json_object_required") -> dict[str, Any]:
    """Read a JSON object body; malformed JSON is 400 and any other JSON type is 422."""
    try:
        payload = await request.json()
    except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError
        raise HTTPException(status_code=400, detail="invalid_json") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail=detail)
    return payload


def _discover_llm_models(provider: str, *, base_url: str, api_key: str) -> list[str]:
    """Call a provider's official model-list API without persisting secrets."""
    import httpx

    transport = httpx.Client(follow_redirects=False, trust_env=False, timeout=C.LLM_PROBE_TIMEOUT_SECONDS)
    if provider == "anthropic":
        import anthropic

        client = anthropic.Anthropic(
            api_key=api_key,
            base_url="https://api.anthropic.com",
            http_client=transport,
            timeout=C.LLM_PROBE_TIMEOUT_SECONDS,
        )
        try:
            return _model_ids(client.models.list(limit=_LLM_MODEL_LIMIT))
        finally:
            client.close()

    from app.llm import client as llm_client

    normalized_url = llm_client._normalize_base_url(
        base_url,
        local_compatible=provider == "lmstudio",
    )
    client = llm_client.OpenAI(
        base_url=normalized_url,
        # LM Studio accepts an arbitrary key, but cloud OpenAI must receive
        # only an actual configured key. The route rejects its empty-key case.
        api_key=(api_key or "lm-studio") if provider == "lmstudio" else api_key,
        timeout=C.LLM_PROBE_TIMEOUT_SECONDS,
        http_client=transport,
    )
    try:
        return _model_ids(client.models.list())
    finally:
        client.close()


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Fails this service's jobs from a previous boot, re-dispatches its orphaned
    # queued jobs, and leaves the API process's live jobs alone.
    recover_jobs_at_boot(get_repo(), get_queue, role="web")
    sweep_task = asyncio.create_task(job_sweep_loop(get_repo()))
    yield
    sweep_task.cancel()
    if get_queue.cache_info().currsize:
        get_queue().shutdown(wait=False)


def _uploads_dir() -> pathlib.Path:
    path = pathlib.Path(os.environ.get("PCAP_HUNTER_API_UPLOADS_DIR", str(UPLOADS_DIR_DEFAULT)))
    path.mkdir(parents=True, exist_ok=True)
    return path


async def _save_upload(upload: UploadFile, destination: pathlib.Path, max_bytes: int) -> None:
    bytes_written = 0
    head = b""
    try:
        with destination.open("wb") as output:
            while chunk := await upload.read(1024 * 1024):
                if not head:
                    head = chunk[:8]
                bytes_written += len(chunk)
                if bytes_written > max_bytes:
                    raise HTTPException(status_code=413, detail=f"{upload.filename}: file is too large")
                output.write(chunk)
        if not is_valid_pcap_magic(head):
            raise HTTPException(status_code=415, detail=f"{upload.filename}: invalid PCAP or PCAPNG file")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def _pipeline_options(include_llm: bool) -> dict[str, Any]:
    config = get_config_manager().load()
    return {
        "osint_enabled": True,
        "llm_enabled": include_llm,
        "do_yara": True,
        "do_carve": True,
        "do_pyshark": True,
        "do_zeek": True,
        "pre_count": True,
        "pyshark_packet_limit": config.get("cfg_pyshark_limit", C.DEFAULT_PYSHARK_LIMIT),
        "osint_top_n": config.get("cfg_osint_top_ips", C.OSINT_TOP_IPS_DEFAULT),
    }


def _json_safe_whois(value: Any) -> Any:
    """Convert python-whois/RDAP values to a bounded JSON-friendly shape."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe_whois(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe_whois(item) for item in value]
    return str(value)


def _allowed_capture_path(value: str) -> pathlib.Path:
    """Resolve a browser-submitted path without escaping configured capture roots."""
    candidate = pathlib.Path(value).expanduser().resolve()
    if candidate.suffix.lower() not in {".pcap", ".pcapng"} or not candidate.is_file():
        raise HTTPException(status_code=422, detail=f"Capture path is not a readable PCAP file: {value}")
    for allowed in C.ALLOWED_PCAP_DIRS:
        try:
            candidate.relative_to(pathlib.Path(allowed).resolve())
            return candidate
        except ValueError:
            continue
    raise HTTPException(status_code=403, detail=f"Capture path is outside the allowed data directories: {value}")


def _create_batch_case(names: list[str], *, path_submission: bool = False) -> Case:
    case_id = uuid.uuid4().hex[:8]
    title = names[0] if len(names) == 1 else f"Batch analysis · {len(names)} captures"
    return Case(
        id=case_id,
        title=title,
        status=CaseStatus.IN_PROGRESS,
        severity=Severity.LOW,
        tags=["ui-path" if path_submission else "ui-batch"] if len(names) > 1 else ["ui"],
    )


def create_app() -> FastAPI:
    app = FastAPI(title="PCAP Threat Hunting Workbench", docs_url=None, redoc_url=None, lifespan=_lifespan)
    app.add_middleware(LocalWorkbenchMiddleware)
    app.include_router(local_agent_router)

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/ui/bootstrap")
    def bootstrap(analysis_id: str | None = None) -> JSONResponse:
        return JSONResponse(build_workbench_state(get_repo(), analysis_id=analysis_id))

    @app.get("/api/ui/cases/{case_id}")
    def case_detail(case_id: str) -> JSONResponse:
        case = get_repo().get_case(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="case_not_found")
        return JSONResponse(case.to_dict())

    @app.get("/api/ui/cases/{case_id}/report.pdf")
    def case_report_pdf(case_id: str) -> FileResponse:
        return build_case_report_response(case_id, get_repo())

    @app.get("/api/ui/geo/continents")
    def geo_continents() -> JSONResponse:
        return JSONResponse({"items": get_continents()})

    @app.get("/api/ui/geo/countries")
    def geo_countries(continent: str) -> JSONResponse:
        return JSONResponse({"items": get_countries(continent)})

    @app.get("/api/ui/geo/cities")
    def geo_cities(country: str) -> JSONResponse:
        return JSONResponse({"items": get_cities(country)})

    @app.get("/api/ui/geo/location")
    def geo_location(country: str, city: str) -> JSONResponse:
        latitude, longitude = get_location_details(city, country)
        if latitude == 0.0 and longitude == 0.0:
            raise HTTPException(status_code=404, detail="location_not_found")
        return JSONResponse({"latitude": latitude, "longitude": longitude})

    @app.get("/api/ui/whois")
    def whois_lookup(target: str) -> JSONResponse:
        normalized = target.strip().rstrip(".").lower()
        try:
            parsed_ip = ipaddress.ip_address(normalized)
        except ValueError:
            parsed_ip = None
        if parsed_ip is not None and not is_public_ipv4(normalized):
            raise HTTPException(status_code=422, detail="Enter a public IP address or valid domain name.")
        if parsed_ip is None and normalized.replace(".", "").isdigit():
            raise HTTPException(status_code=422, detail="Enter a public IP address or valid domain name.")
        kind = "IP" if parsed_ip is not None else "Domain"
        if kind == "Domain" and not _validate_domain(normalized):
            raise HTTPException(status_code=422, detail="Enter a public IP address or valid domain name.")

        info = get_whois_info(normalized)
        if isinstance(info, str):
            raise HTTPException(status_code=502, detail=info)
        if isinstance(info, dict) and info.get("error"):
            raise HTTPException(status_code=422, detail=str(info["error"]))
        try:
            record = dict(info)
        except (TypeError, ValueError):
            record = {"raw": getattr(info, "text", str(info))}
        return JSONResponse({"target": normalized, "kind": kind, "record": _json_safe_whois(record)})

    @app.post("/api/ui/cases", status_code=201)
    async def create_case_record(request: Request) -> JSONResponse:
        payload = await _json_object(request, detail="case_object_required")
        raw_tags = payload.get("tags")
        if raw_tags is None:
            raw_tags = []
        if not isinstance(raw_tags, list) or not all(isinstance(tag, (str, int, float)) for tag in raw_tags):
            raise HTTPException(status_code=422, detail="tags_must_be_a_list_of_text")
        for field in ("title", "description", "severity"):
            if payload.get(field) is not None and not isinstance(payload[field], str):
                raise HTTPException(status_code=422, detail=f"{field}_must_be_a_string")
        title = (payload.get("title") or "").strip()[:300] or "Untitled investigation"
        case = Case(
            id=uuid.uuid4().hex[:8],
            title=title,
            description=payload.get("description") or "",
            status=CaseStatus.OPEN,
            severity=Severity.from_str(payload.get("severity") or "low"),
            tags=[str(tag).strip()[:100] for tag in raw_tags if str(tag).strip()][:20],
        )
        get_repo().create_case(case)
        return JSONResponse({"id": case.id}, status_code=201)

    @app.post("/api/ui/cases/{case_id}/notes")
    async def add_case_note(case_id: str, request: Request) -> JSONResponse:
        case = get_repo().get_case(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="case_not_found")
        payload = await _json_object(request, detail="note_object_required")
        if payload.get("content") is not None and not isinstance(payload["content"], str):
            raise HTTPException(status_code=422, detail="note_must_be_a_string")
        content = (payload.get("content") or "").strip()
        if not content:
            raise HTTPException(status_code=422, detail="note_required")
        note_id = get_repo().add_note(case_id, content)
        return JSONResponse({"id": note_id, "content": content})

    @app.post("/api/ui/uploads", status_code=202)
    async def upload_pcaps(
        files: list[UploadFile] = File(...),
        include_llm: bool = True,
    ) -> JSONResponse:
        if not files:
            raise HTTPException(status_code=422, detail="at_least_one_capture_required")
        if len(files) > 50:
            raise HTTPException(status_code=422, detail="maximum_50_captures")

        capture_names = [file.filename or f"capture-{index + 1}.pcap" for index, file in enumerate(files)]
        case = _create_batch_case(capture_names)
        case_id = case.id
        repo = get_repo()
        repo.create_case(case)
        queue = get_queue()
        jobs: list[dict[str, str]] = []
        saved_paths: list[pathlib.Path] = []
        try:
            for index, upload in enumerate(files):
                suffix = pathlib.Path(upload.filename or "capture.pcap").suffix.lower()
                suffix = suffix if suffix in {".pcap", ".pcapng"} else ".pcap"
                destination = _uploads_dir() / f"{case_id}_{index + 1}{suffix}"
                await _save_upload(upload, destination, get_settings().max_pcap_bytes)
                saved_paths.append(destination)
                job_id = queue.enqueue(
                    JobSubmission(
                        case_id=case_id,
                        pcap_path=str(destination),
                        options={**_pipeline_options(include_llm), "display_name": capture_names[index]},
                    )
                )
                jobs.append({"job_id": job_id, "name": capture_names[index]})
        except QueueFullError as exc:
            for path in saved_paths:
                path.unlink(missing_ok=True)
            repo.delete_case(case_id)
            raise HTTPException(status_code=503, detail="analysis_queue_full") from exc
        except BaseException:
            for path in saved_paths:
                path.unlink(missing_ok=True)
            repo.delete_case(case_id)
            raise
        return JSONResponse({"case_id": case_id, "jobs": jobs}, status_code=202)

    @app.post("/api/ui/paths", status_code=202)
    async def submit_capture_paths(request: Request) -> JSONResponse:
        payload = await _json_object(request, detail="at_least_one_capture_path_required")
        raw_paths = payload.get("paths")
        if not isinstance(raw_paths, list) or not raw_paths:
            raise HTTPException(status_code=422, detail="at_least_one_capture_path_required")
        if len(raw_paths) > 50:
            raise HTTPException(status_code=422, detail="maximum_50_captures")
        if not all(isinstance(value, str) for value in raw_paths):
            raise HTTPException(status_code=422, detail="capture_paths_must_be_strings")
        paths = [_allowed_capture_path(value.strip()) for value in raw_paths]
        include_llm = bool(payload.get("include_llm", True))
        case = _create_batch_case([path.name for path in paths], path_submission=True)
        repo = get_repo()
        repo.create_case(case)
        jobs: list[dict[str, str]] = []
        try:
            queue = get_queue()
            for path in paths:
                job_id = queue.enqueue(
                    JobSubmission(
                        case_id=case.id,
                        pcap_path=str(path),
                        options={**_pipeline_options(include_llm), "display_name": path.name},
                    )
                )
                jobs.append({"job_id": job_id, "name": path.name})
        except QueueFullError as exc:
            repo.delete_case(case.id)
            raise HTTPException(status_code=503, detail="analysis_queue_full") from exc
        except BaseException:
            repo.delete_case(case.id)
            raise
        return JSONResponse({"case_id": case.id, "jobs": jobs}, status_code=202)

    @app.get("/api/ui/jobs")
    def list_ui_jobs() -> JSONResponse:
        """Job list only, in the same shape as the bootstrap payload's ``jobs``.

        Lets the client poll run progress without rebuilding the whole
        workbench state (dashboard, cases, config) on every tick.
        """
        return JSONResponse({"jobs": serialize_jobs(get_repo())})

    @app.get("/api/ui/settings")
    def get_ui_settings() -> JSONResponse:
        return JSONResponse(public_config())

    @app.put("/api/ui/settings")
    async def save_ui_settings(request: Request) -> JSONResponse:
        payload = await _json_object(request, detail="settings_object_required")

        def _save() -> tuple[dict[str, str], list[str]]:
            manager = get_config_manager()
            file_lock = getattr(manager, "_lock", None)
            # One critical section for load -> validate -> merge -> save, so two
            # concurrent saves cannot interleave and drop each other's fields.
            with _SETTINGS_LOCK, file_lock if hasattr(file_lock, "__enter__") else nullcontext():
                current = manager.load()
                errors, cleared = _apply_settings_update(current, payload)
                if not errors:
                    manager.save({key: value for key, value in current.items() if key in CONFIG_KEYS})
                return errors, cleared

        errors, cleared = await run_in_threadpool(_save)
        if errors:
            summary = "; ".join(f"{key} {message}" for key, message in sorted(errors.items()))
            return JSONResponse(
                {
                    "detail": f"Settings were not saved: {summary}.",
                    "errors": [{"field": key, "message": message} for key, message in sorted(errors.items())],
                },
                status_code=422,
            )
        body: dict[str, Any] = {"saved": True}
        if cleared:
            body["cleared_keys"] = cleared
            body["notice"] = (
                "The provider API URL now points at a different host, so its stored API key was cleared. "
                "Enter the key for the new host and save again."
            )
        return JSONResponse(body)

    @app.post("/api/ui/llm/models")
    async def discover_llm_models(request: Request) -> JSONResponse:
        """Fetch a provider's model list for the settings form.

        The client may supply unsaved values while editing settings.  They are
        used for this single request only and are never returned or persisted.
        """
        try:
            payload = await request.json()
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="llm_model_request_required") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="llm_model_request_required")

        raw_provider = payload.get("provider")
        if not isinstance(raw_provider, str) or raw_provider not in _LLM_PROVIDERS:
            raise HTTPException(status_code=422, detail="unsupported_llm_provider")
        provider = raw_provider
        saved = get_config_manager().load()

        if provider == "lmstudio":
            base_url = _draft_value(payload, "base_url", saved.get("cfg_llm_endpoint"))
            api_key = _destination_key(
                payload, saved.get("cfg_openai_key"), base_url, str(saved.get("cfg_llm_endpoint") or "")
            )
            if not base_url:
                raise HTTPException(status_code=422, detail="llm_base_url_required")
            base_url = _validated_model_base_url(base_url)
            if not api_key:
                # Environment key only for the deployment's own origin; otherwise keyless.
                environment_key = resolve_llm_api_key(provider, base_url, None)[0]
                api_key = "" if environment_key == LMSTUDIO_PLACEHOLDER_KEY else environment_key
        elif provider == "openai":
            base_url = _draft_value(payload, "base_url", saved.get("cfg_openai_base_url"))
            base_url = _validated_model_base_url(base_url or "https://api.openai.com/v1")
            api_key = _destination_key(
                payload,
                saved.get("cfg_openai_cloud_key"),
                base_url,
                str(saved.get("cfg_openai_base_url") or "https://api.openai.com/v1"),
            )
            if not api_key:
                # Environment key only for the deployment's own origin, exactly as the worker does.
                api_key = resolve_llm_api_key(provider, base_url, None)[0]
            if not api_key:
                raise HTTPException(status_code=422, detail="openai_api_key_required")
        else:
            # Anthropic's official SDK does not accept a user supplied base URL.
            base_url = ""
            api_key = _draft_value(payload, "api_key", saved.get("cfg_anthropic_key"))
            api_key = resolve_llm_api_key(provider, base_url, api_key)[0]
            if not api_key:
                raise HTTPException(status_code=422, detail="anthropic_api_key_required")

        try:
            models = _model_ids(
                await run_in_threadpool(
                    _discover_llm_models,
                    provider,
                    base_url=base_url,
                    api_key=api_key,
                )
            )
        except HTTPException:
            raise
        except Exception:
            # Provider SDK errors can include request URLs and authorization
            # details; do not expose or log them from this UI endpoint.
            logger.warning("Model discovery failed for LLM provider %s", provider)
            return JSONResponse(
                {
                    "models": [],
                    "message": "Could not retrieve models. Check the provider settings and try again.",
                },
                status_code=502,
            )

        label = _LLM_PROVIDER_LABELS[provider]
        message = f"{label} returned {len(models)} model{'s' if len(models) != 1 else ''}."
        if not models:
            message = f"{label} returned no models."
        return JSONResponse({"models": models, "message": message})

    @app.get("/{asset_path:path}")
    def frontend(asset_path: str) -> FileResponse:
        candidate = (STATIC_DIR / asset_path).resolve()
        try:
            candidate.relative_to(STATIC_DIR.resolve())
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="not_found") from exc
        if asset_path and candidate.is_file():
            return FileResponse(candidate)
        index = STATIC_DIR / "index.html"
        if not index.is_file():
            raise HTTPException(status_code=503, detail="frontend_not_built")
        return FileResponse(index)

    return app
