"""Tests for file utility functions."""

from __future__ import annotations

from app.utils.file_utils import ensure_dir, sha256_bytes


class TestSha256Bytes:
    def test_known_hash(self):
        # SHA256 of empty bytes
        assert sha256_bytes(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_non_empty(self):
        result = sha256_bytes(b"hello")
        assert len(result) == 64
        assert result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_deterministic(self):
        assert sha256_bytes(b"test") == sha256_bytes(b"test")

    def test_different_input_different_hash(self):
        assert sha256_bytes(b"a") != sha256_bytes(b"b")


class TestEnsureDir:
    def test_creates_directory(self, tmp_path):
        new_dir = tmp_path / "sub" / "deep"
        assert not new_dir.exists()
        ensure_dir(new_dir)
        assert new_dir.is_dir()

    def test_existing_directory(self, tmp_path):
        ensure_dir(tmp_path)  # Should not raise

    def test_nested_creation(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c"
        ensure_dir(deep)
        assert deep.is_dir()
