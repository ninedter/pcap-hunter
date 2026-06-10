class CarveError(Exception):
    """Raised when HTTP payload carving fails."""


def carve_http_payloads(pcap_path: str, out_dir: str, phase=None) -> list[dict]:
    import hashlib
    import logging
    import pathlib
    import subprocess
    import threading

    from app import config as C
    from app.utils.common import find_bin

    logger = logging.getLogger(__name__)

    pathlib.Path(out_dir).mkdir(parents=True, exist_ok=True)

    tshark_bin = find_bin("tshark", cfg_key="cfg_tshark_bin")
    if not tshark_bin:
        msg = "Tshark binary not found for carving."
        logger.warning(msg)
        if phase:
            phase.done("Tshark missing.")
        raise CarveError(msg)

    if phase and phase.should_skip():
        phase.done("HTTP carving skipped.")
        return []

    if phase:
        phase.set(5, "Running tshark…")
    cmd = [
        tshark_bin,
        "-r",
        pcap_path,
        "-Y",
        "http && http.file_data",
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
        "-e",
        "tcp.stream",
        "-e",
        "http.content_type",
        "-e",
        "http.content_length",
        "-e",
        "http.file_data",
    ]
    try:
        # Stream stdout line by line instead of buffering every carved body in
        # RAM at once — this is a full-file tshark pass with no upfront size cap.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        if phase:
            phase.done("tshark failed.")
        raise CarveError(f"tshark exec failed: {e}") from e

    # Read at call time (not import time) so config/monkeypatch changes apply.
    timeout_s = C.CARVE_TIMEOUT_SECONDS
    timed_out = threading.Event()

    def _kill() -> None:
        timed_out.set()
        proc.kill()

    watchdog = threading.Timer(timeout_s, _kill)
    watchdog.start()

    results = []
    processed = 0
    skipped_early = False
    try:
        for line in proc.stdout:
            if phase and phase.should_skip():
                skipped_early = True
                break
            line = line.rstrip("\n")
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            ts, stream_id, ctype, clen, body = parts[:5]
            if isinstance(body, str):
                data_bytes = body.encode("utf-8", "surrogateescape")
            else:
                data_bytes = body
            h = hashlib.sha256(data_bytes).hexdigest()
            fname = f"stream{stream_id}_{h[:10]}.bin"
            fpath = pathlib.Path(out_dir) / fname
            try:
                fpath.write_bytes(data_bytes)
            except OSError as e:
                logger.warning("Failed to write carved file %s: %s", fpath, e)
                continue
            results.append(
                {
                    "time": ts,
                    "tcp_stream": stream_id,
                    "content_type": ctype,
                    "content_length": clen,
                    "sha256": h,
                    "path": str(fpath),
                }
            )
            processed += 1
            if phase:
                # Total line count is unknown while streaming: capped monotone progression.
                phase.set(min(90, 10 + processed // 25), f"Carved {processed}")
        if not skipped_early:
            # Watchdog is still armed here, so a child that closed stdout but
            # refuses to exit is killed rather than hanging the pool thread.
            proc.wait()
    finally:
        watchdog.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    if timed_out.is_set():
        if phase:
            phase.done("tshark carve timed out.")
        raise CarveError(f"tshark carve timed out after {timeout_s}s")

    if phase:
        if phase.should_skip():
            phase.done("HTTP carving skipped.")
        else:
            phase.done(f"Carved {len(results)} bodies.")
    return results
