"""Tests for YARA scanning module."""

import tempfile
from pathlib import Path

import pytest

import app.config as config_module
from app.pipeline.yara_scan import (
    YARA_AVAILABLE,
    YARAMatch,
    YARAScanner,
    YARAScanResult,
    scan_carved_files,
)


class TestYARAScanResult:
    """Test YARAScanResult dataclass."""

    def test_empty_result(self):
        result = YARAScanResult(
            file_path="/tmp/test.bin",
            file_hash="abc123",
            file_size=100,
        )
        assert result.has_matches is False
        assert result.severity == "clean"

    def test_with_matches(self):
        match = YARAMatch(
            rule_name="test_rule",
            rule_tags=["malware"],
            meta={"author": "test"},
            strings=[(0, "$s1", b"test")],
            file_path="/tmp/test.bin",
            file_hash="abc123",
        )
        result = YARAScanResult(
            file_path="/tmp/test.bin",
            file_hash="abc123",
            file_size=100,
            matches=[match],
        )
        assert result.has_matches is True
        assert result.severity == "critical"

    def test_severity_levels(self):
        """Test different severity levels based on tags."""

        def make_result(tags):
            match = YARAMatch(
                rule_name="test",
                rule_tags=tags,
                meta={},
                strings=[],
                file_path="/tmp/test.bin",
                file_hash="abc123",
            )
            return YARAScanResult(
                file_path="/tmp/test.bin",
                file_hash="abc123",
                file_size=100,
                matches=[match],
            )

        # Critical tags
        assert make_result(["malware"]).severity == "critical"
        assert make_result(["trojan"]).severity == "critical"
        assert make_result(["ransomware"]).severity == "critical"
        assert make_result(["backdoor"]).severity == "critical"

        # High severity tags
        assert make_result(["suspicious"]).severity == "high"
        assert make_result(["packed"]).severity == "high"
        assert make_result(["obfuscated"]).severity == "high"

        # Medium severity tags
        assert make_result(["pup"]).severity == "medium"
        assert make_result(["adware"]).severity == "medium"
        assert make_result(["miner"]).severity == "medium"

        # Low severity for other tags
        assert make_result(["info"]).severity == "low"

    def test_to_dict(self):
        result = YARAScanResult(
            file_path="/tmp/test.bin",
            file_hash="abc123",
            file_size=100,
            scan_time=0.5,
        )
        d = result.to_dict()
        assert d["file_path"] == "/tmp/test.bin"
        assert d["file_hash"] == "abc123"
        assert d["file_size"] == 100
        assert d["scan_time"] == 0.5
        assert d["severity"] == "clean"
        assert d["has_matches"] is False


class TestYARAMatch:
    """Test YARAMatch dataclass."""

    def test_to_dict(self):
        match = YARAMatch(
            rule_name="test_rule",
            rule_tags=["malware", "pe"],
            meta={"author": "test", "description": "Test rule"},
            strings=[(0, "$mz", b"MZ"), (100, "$sig", b"badcode")],
            file_path="/tmp/test.bin",
            file_hash="abc123",
        )
        d = match.to_dict()
        assert d["rule_name"] == "test_rule"
        assert d["rule_tags"] == ["malware", "pe"]
        assert d["meta"] == {"author": "test", "description": "Test rule"}
        assert len(d["strings"]) == 2
        assert d["strings"][0]["offset"] == 0
        assert d["strings"][0]["identifier"] == "$mz"
        assert d["strings"][0]["data"] == "4d5a"  # "MZ" in hex

    def test_strings_limit(self):
        """Test that strings are limited to 10."""
        match = YARAMatch(
            rule_name="test",
            rule_tags=[],
            meta={},
            strings=[(i, f"$s{i}", b"x") for i in range(20)],
            file_path="/tmp/test.bin",
            file_hash="abc123",
        )
        d = match.to_dict()
        assert len(d["strings"]) == 10


class TestYARAScanner:
    """Test YARAScanner class."""

    def test_init_without_rules(self):
        """Test scanner initialization without rules directory."""
        scanner = YARAScanner(rules_dirs=["/nonexistent/path"])
        assert scanner.rule_count == 0

    def test_is_available(self):
        """Test availability check."""
        scanner = YARAScanner(rules_dirs=[])
        # If yara-python is installed, is_available depends on rules
        # If not installed, is_available should be False
        if not YARA_AVAILABLE:
            assert scanner.is_available is False

    def test_scan_nonexistent_file(self):
        """Test scanning a file that doesn't exist."""
        scanner = YARAScanner(rules_dirs=[])
        result = scanner.scan_file("/nonexistent/file.bin")
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_scan_directory_invalid(self):
        """Test scanning invalid directory."""
        scanner = YARAScanner(rules_dirs=[])
        result = scanner.scan_directory("/nonexistent/dir")
        assert "error" in result
        assert "Invalid directory" in result["error"]

    def test_scan_empty_file(self):
        """Test scanning an empty file."""
        scanner = YARAScanner(rules_dirs=[])
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            result = scanner.scan_file(temp_path)
            assert result.error is not None
            assert "empty" in result.error.lower()
        finally:
            Path(temp_path).unlink()

    def test_scan_carved_empty(self):
        """Test scanning empty carved list."""
        scanner = YARAScanner(rules_dirs=[])
        result = scanner.scan_carved([])
        assert result["scanned"] == 0
        assert result["matched"] == 0

    def test_scan_carved_no_path(self):
        """Test scanning carved items without path."""
        scanner = YARAScanner(rules_dirs=[])
        result = scanner.scan_carved([{"content_type": "text/html"}])
        assert result["scanned"] == 0

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
    def test_scan_with_rules(self):
        """Test scanning with actual YARA rules."""
        # Create temp file with known content
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"MZ" + b"\x00" * 100)  # PE header signature
            temp_path = f.name

        try:
            # Use default rules directory
            scanner = YARAScanner()
            if scanner.is_available:
                result = scanner.scan_file(temp_path)
                assert result.file_size == 102
                assert result.file_hash != ""
        finally:
            Path(temp_path).unlink()

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
    def test_add_custom_rules_nonexistent(self):
        """Test adding non-existent custom rules."""
        scanner = YARAScanner()
        result = scanner.add_custom_rules("/nonexistent/rules")
        assert result is False


class TestScanCarvedFiles:
    """Test convenience function."""

    def test_scan_carved_files_empty(self):
        """Test with empty list."""
        result = scan_carved_files([])
        assert result["scanned"] == 0

    def test_scan_carved_files_with_custom_rules_dir(self):
        """Test with custom rules directory."""
        result = scan_carved_files([], rules_dirs=["/nonexistent"])
        assert result["scanned"] == 0


class TestFileSizeLimit:
    """Test file size limit handling."""

    def test_max_file_size_constant(self):
        """Test that MAX_FILE_SIZE is set correctly."""
        scanner = YARAScanner()
        assert scanner.MAX_FILE_SIZE == 100 * 1024 * 1024  # 100MB

    def test_max_scan_timeout_constant(self):
        """Test that MAX_SCAN_TIMEOUT is set correctly."""
        scanner = YARAScanner()
        assert scanner.MAX_SCAN_TIMEOUT == 60  # 60 seconds


# Minimal valid YARA rule used across default-lookup tests
_TRIVIAL_YARA_RULE = b"rule trivial { condition: false }"


class TestDefaultLookup:
    """Tests for the zero-config DATA_DIR/yara_rules default lookup."""

    def test_default_lookup_picks_up_yara_rules_dir(self, monkeypatch, tmp_path):
        """YARAScanner picks up DATA_DIR/yara_rules when it exists."""
        # Create tmp DATA_DIR / yara_rules with a trivial rule file
        yara_rules_dir = tmp_path / "yara_rules"
        yara_rules_dir.mkdir()
        rule_file = yara_rules_dir / "test.yar"
        rule_file.write_bytes(_TRIVIAL_YARA_RULE)

        # Patch config.DATA_DIR so the scanner resolves to our tmp dir
        monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)

        scanner = YARAScanner()
        # The scanner should have discovered the directory
        assert any(d == yara_rules_dir for d in scanner._rules_dirs)

    def test_explicit_rules_dirs_wins_over_default(self, monkeypatch, tmp_path):
        """An explicit rules_dirs argument is used instead of defaults."""
        # Create the default fallback dir — it must NOT be picked when explicit is given
        yara_rules_dir = tmp_path / "yara_rules"
        yara_rules_dir.mkdir()
        monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)

        # Create a separate explicit dir
        explicit_dir = tmp_path / "custom_rules"
        explicit_dir.mkdir()
        (explicit_dir / "custom.yar").write_bytes(_TRIVIAL_YARA_RULE)

        scanner = YARAScanner(rules_dirs=[str(explicit_dir)])
        assert any(d == explicit_dir for d in scanner._rules_dirs)
        # Default yara_rules dir should NOT be present
        assert not any(d == yara_rules_dir for d in scanner._rules_dirs)

    def test_nonexistent_configured_dir_excluded(self, tmp_path):
        """A nonexistent explicit rules_dir is excluded; scanner does not crash."""
        nonexistent = str(tmp_path / "does_not_exist")
        scanner = YARAScanner(rules_dirs=[nonexistent])
        # Should not crash, and the nonexistent dir should not be in _rules_dirs
        assert not any(str(d) == nonexistent for d in scanner._rules_dirs)

    def test_nonexistent_configured_dir_scan_graceful(self, tmp_path):
        """scan_carved_files with a nonexistent configured dir falls back gracefully."""
        nonexistent = str(tmp_path / "missing_rules")
        # Should not raise; returns a result dict with scanned=0
        result = scan_carved_files([], rules_dirs=[nonexistent])
        assert result["scanned"] == 0
