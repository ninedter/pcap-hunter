"""Tests for Streamlit upload helpers."""

from __future__ import annotations

import io

import pytest

from app.ui.upload import CHUNK_SIZE, UploadValidationError, save_uploaded_pcaps


class FakeUpload(io.BytesIO):
    def __init__(self, name: str, payload: bytes):
        super().__init__(payload)
        self.name = name
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return super().read(size)


def test_save_uploaded_pcaps_streams_chunks_and_preserves_suffix(tmp_path):
    payload = b"\x0a\x0d\x0d\x0a" + b"x" * (CHUNK_SIZE + 10)
    upload = FakeUpload("sample.pcapng", payload)

    saved = save_uploaded_pcaps([upload], tmp_path, timestamp=123, run_id="abc12345")

    assert saved[0].original_name == "sample.pcapng"
    assert saved[0].path.endswith("upload_123_abc12345_0.pcapng")
    assert saved[0].size_bytes == len(payload)
    assert upload.read_sizes[0] == CHUNK_SIZE
    assert (tmp_path / "upload_123_abc12345_0.pcapng").read_bytes() == payload


def test_save_uploaded_pcaps_rejects_invalid_magic_and_removes_file(tmp_path):
    upload = FakeUpload("bad.pcap", b"PK\x03\x04" + b"x" * 20)

    with pytest.raises(UploadValidationError, match="not a valid PCAP"):
        save_uploaded_pcaps([upload], tmp_path, timestamp=123)

    assert not list(tmp_path.iterdir())


def test_save_uploaded_pcaps_cleans_earlier_files_on_batch_failure(tmp_path):
    good = FakeUpload("good.pcap", b"\xd4\xc3\xb2\xa1" + b"x" * 20)
    bad = FakeUpload("bad.pcap", b"PK\x03\x04" + b"x" * 20)

    with pytest.raises(UploadValidationError):
        save_uploaded_pcaps([good, bad], tmp_path, timestamp=123)

    assert not list(tmp_path.iterdir())
