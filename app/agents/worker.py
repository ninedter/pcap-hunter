"""Offline worker entry point. Mount only agent spool, never app data or secrets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from app.agents.spool import atomic_json, input_root, output_root


def process(job_id):
    from app.agents.provenance import capture_provenance
    from app.pipeline.progress import CallbackProgress
    from app.pipeline.runner import PipelineOptions, run_pipeline
    from app.pipeline.yara_scan import scan_carved_files

    inbox = input_root() / job_id
    request = json.loads((inbox / "request.json").read_text())
    if request["job_id"] != job_id or not re.fullmatch(r"[a-f0-9]{12}", request["case_id"]):
        raise ValueError("invalid job")
    capture = inbox / "capture.pcap"
    if capture.is_symlink() or not capture.is_file() or capture.stat().st_size > 100 * 1024 * 1024:
        raise ValueError("invalid capture")
    options = {"osint_enabled": False, "llm_enabled": False, "pyshark_packet_limit": 200000}

    def on_progress(event):
        atomic_json(
            output_root() / (job_id + ".progress"),
            {"stage": event.title[:100], "kind": event.kind, "heartbeat": time.time()},
        )

    result = run_pipeline(str(capture), request["case_id"], PipelineOptions(**options), CallbackProgress(on_progress))
    data = result.to_dict() | {"features": result.features}
    if result.carved_items:
        data["yara_results"] = scan_carved_files(result.carved_items)
    provenance = capture_provenance(SimpleNamespace(id=job_id, pcap_path=str(capture)), options)
    provenance["completed_at"] = datetime.now(timezone.utc).isoformat()
    with capture.open("rb") as source:
        input_hash = hashlib.file_digest(source, "sha256").hexdigest()
    payload = {"ok": True, "input_sha256": input_hash, "provenance": provenance, "result": data}
    output = output_root() / (job_id + ".json")
    if len(json.dumps(payload)) > 32 * 1024 * 1024:
        raise ValueError("result too large")
    atomic_json(output, payload)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--job", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"j_[a-f0-9]{16}", args.job):
        raise ValueError("invalid job id")
    if input_root() != Path("/job/inbox") or output_root() != Path("/job/results"):
        raise ValueError("Worker requires a private job container; start the supervisor instead")
    if os.getenv("PCAP_HUNTER_DATA_DIR") != "/job/work":
        raise ValueError("Worker requires private scratch storage")
    for name in ("tmp", "home", "work", "results"):
        Path("/job", name).mkdir(exist_ok=True)
    try:
        process(args.job)
    except Exception:
        atomic_json(output_root() / (args.job + ".json"), {"ok": False, "error_code": "offline_worker_failed"})
    # Keep tmpfs mounted until the trusted supervisor collects the bounded result.
    # The supervisor then removes the entire container, including any parser children.
    time.sleep(120)


if __name__ == "__main__":
    main()
