"""Production PCAP Hunter web workbench.

The React shell is served from the same local-only process as its UI API so the
approved prototype can become the real product without browser-side API keys.
"""

from __future__ import annotations

import ipaddress
import os
import pathlib
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import date, datetime
from typing import Any

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from app import config as C
from app.api.deps import get_queue, get_repo, get_settings
from app.api.queue import JobSubmission, QueueFullError, recover_stale_running_jobs
from app.api.routers.cases import build_case_report_response
from app.api.validation import is_valid_pcap_magic
from app.database.models import Case, CaseStatus, Severity
from app.utils.config_manager import SENSITIVE_KEYS, get_config_manager
from app.utils.geo_data import get_cities, get_continents, get_countries, get_location_details
from app.utils.network_utils import _validate_domain, get_whois_info, is_public_ipv4
from app.web.state import build_workbench_state

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


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    recover_stale_running_jobs(get_repo(), stale_after_seconds=120)
    yield
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

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/ui/bootstrap")
    def bootstrap() -> JSONResponse:
        return JSONResponse(build_workbench_state(get_repo()))

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
        payload = await request.json()
        title = str(payload.get("title") or "Untitled investigation").strip()
        case = Case(
            id=uuid.uuid4().hex[:8],
            title=title,
            description=str(payload.get("description") or ""),
            status=CaseStatus.OPEN,
            severity=Severity.from_str(str(payload.get("severity") or "low")),
            tags=[str(tag) for tag in payload.get("tags", []) if str(tag).strip()][:20],
        )
        get_repo().create_case(case)
        return JSONResponse({"id": case.id}, status_code=201)

    @app.post("/api/ui/cases/{case_id}/notes")
    async def add_case_note(case_id: str, request: Request) -> JSONResponse:
        case = get_repo().get_case(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="case_not_found")
        payload = await request.json()
        content = str(payload.get("content") or "").strip()
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
        payload = await request.json()
        raw_paths = payload.get("paths") if isinstance(payload, dict) else None
        if not isinstance(raw_paths, list) or not raw_paths:
            raise HTTPException(status_code=422, detail="at_least_one_capture_path_required")
        if len(raw_paths) > 50:
            raise HTTPException(status_code=422, detail="maximum_50_captures")
        paths = [_allowed_capture_path(str(value).strip()) for value in raw_paths]
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

    @app.get("/api/ui/settings")
    def get_ui_settings() -> JSONResponse:
        return JSONResponse(build_workbench_state(get_repo())["config"])

    @app.put("/api/ui/settings")
    async def save_ui_settings(request: Request) -> JSONResponse:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="settings_object_required")
        manager = get_config_manager()
        current = manager.load()
        for key, value in payload.items():
            if key not in CONFIG_KEYS:
                continue
            if key in SENSITIVE_KEYS and value in (None, ""):
                continue
            current[key] = value
        manager.save({key: value for key, value in current.items() if key in CONFIG_KEYS})
        return JSONResponse({"saved": True})

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
