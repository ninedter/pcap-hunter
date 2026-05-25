"""Health and readiness endpoints — no auth required."""

from __future__ import annotations

import shutil

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_queue, get_repo

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz")
def readyz(repo=Depends(get_repo), queue=Depends(get_queue)) -> dict:
    failures: list[str] = []

    # DB check
    try:
        conn = repo._get_conn()
        conn.execute("SELECT 1").fetchone()
        conn.close()
    except Exception as exc:
        failures.append(f"db: {exc}")

    # Disk space check (>= 1 GiB free)
    try:
        usage = shutil.disk_usage(str(repo._db_path.parent))
        if usage.free < 1024**3:
            failures.append(f"disk: {usage.free} bytes free")
    except Exception as exc:
        failures.append(f"disk: {exc}")

    if failures:
        raise HTTPException(status_code=503, detail={"checks_failed": failures})
    return {"status": "ready"}
