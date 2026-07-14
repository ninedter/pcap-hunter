"""Upload helpers for the Streamlit PCAP intake flow."""

from __future__ import annotations

import pathlib
import time
import uuid
from dataclasses import dataclass
from typing import BinaryIO, Iterable

from app import config as C
from app.utils.common import ensure_dir
from app.utils.pcap_validation import is_valid_pcap_magic

CHUNK_SIZE = 1024 * 1024
ALLOWED_UPLOAD_SUFFIXES = frozenset({".pcap", ".pcapng"})


class UploadValidationError(ValueError):
    """Raised when an uploaded PCAP should be rejected before analysis."""


@dataclass(frozen=True)
class SavedUpload:
    """Metadata for a PCAP uploaded through Streamlit."""

    path: str
    original_name: str
    size_bytes: int


def _upload_suffix(name: str) -> str:
    suffix = pathlib.Path(name or "").suffix.lower()
    if suffix not in ALLOWED_UPLOAD_SUFFIXES:
        raise UploadValidationError("Uploaded files must be .pcap or .pcapng.")
    return suffix


def _read_chunks(uploaded: BinaryIO) -> Iterable[bytes]:
    while True:
        chunk = uploaded.read(CHUNK_SIZE)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        yield chunk


def save_uploaded_pcaps(
    uploaded_files: list[BinaryIO],
    data_dir: pathlib.Path | str = C.DATA_DIR,
    *,
    timestamp: int | None = None,
    run_id: str | None = None,
    max_file_size: int = C.BATCH_MAX_FILE_SIZE_BYTES,
    max_total_size: int = C.BATCH_MAX_TOTAL_SIZE_BYTES,
) -> list[SavedUpload]:
    """Stream uploaded PCAPs to disk with size and magic-byte validation.

    Any validation failure removes files written by this call so the UI does not
    leave half-accepted uploads behind.
    """
    if not uploaded_files:
        return []

    target_dir = pathlib.Path(data_dir).resolve()
    ensure_dir(target_dir)
    ts = int(time.time()) if timestamp is None else timestamp
    token = run_id or uuid.uuid4().hex[:8]
    saved: list[SavedUpload] = []
    total_size = 0

    try:
        for index, uploaded in enumerate(uploaded_files):
            original_name = getattr(uploaded, "name", f"upload_{index}.pcap") or f"upload_{index}.pcap"
            suffix = _upload_suffix(original_name)
            save_path = target_dir / f"upload_{ts}_{token}_{index}{suffix}"
            size = 0
            head = b""

            with save_path.open("wb") as fh:
                for chunk in _read_chunks(uploaded):
                    if len(head) < 8:
                        head += chunk[: 8 - len(head)]
                    size += len(chunk)
                    total_size += len(chunk)
                    if size > max_file_size:
                        raise UploadValidationError(f"{original_name} is too large ({size / (1024**2):.1f} MB).")
                    if total_size > max_total_size:
                        raise UploadValidationError(f"Uploaded batch is too large ({total_size / (1024**2):.1f} MB).")
                    fh.write(chunk)

            if size == 0:
                raise UploadValidationError(f"{original_name} is empty.")
            if not is_valid_pcap_magic(head):
                raise UploadValidationError(f"{original_name} is not a valid PCAP/PCAPNG file.")

            saved.append(SavedUpload(path=str(save_path), original_name=original_name, size_bytes=size))
    except Exception:
        for item in saved:
            pathlib.Path(item.path).unlink(missing_ok=True)
        if "save_path" in locals():
            save_path.unlink(missing_ok=True)
        raise

    return saved
