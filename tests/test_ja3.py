"""Tests for JA3 TLS fingerprint functionality."""

import pandas as pd
import pytest

from app.pipeline.ja3 import (
    KNOWN_JA3_FINGERPRINTS,
    analyze_ja3_results,
    calculate_ja3,
    extract_ja3_from_multiple_runs,
    extract_ja3_from_zeek,
    lookup_ja3,
)


class TestCalculateJA3:
    def test_calculate_ja3_basic(self):
        """Calculate JA3 hash from TLS parameters."""
        ja3_hash = calculate_ja3(
            version="771",
            ciphers=["49195", "49196"],
            extensions=["0", "23"],
            curves=["29", "23"],
            point_formats=["0"],
        )
        assert len(ja3_hash) == 32
        assert ja3_hash.isalnum()

    def test_calculate_ja3_deterministic(self):
        """Same inputs produce same hash."""
        params = {
            "version": "771",
            "ciphers": ["49195", "49196"],
            "extensions": ["0"],
            "curves": ["29"],
            "point_formats": ["0"],
        }
        hash1 = calculate_ja3(**params)
        hash2 = calculate_ja3(**params)
        assert hash1 == hash2

    def test_calculate_ja3_different_inputs(self):
        """Different inputs produce different hashes."""
        hash1 = calculate_ja3("771", ["49195"], ["0"], ["29"], ["0"])
        hash2 = calculate_ja3("771", ["49196"], ["0"], ["29"], ["0"])
        assert hash1 != hash2

    def test_calculate_ja3_empty_version_raises(self):
        """Empty version should raise ValueError."""
        with pytest.raises(ValueError, match="TLS version is required"):
            calculate_ja3("", ["49195"], ["0"], ["29"], ["0"])

    def test_calculate_ja3_none_version_raises(self):
        """None version should raise ValueError."""
        with pytest.raises(ValueError, match="TLS version is required"):
            calculate_ja3(None, ["49195"], ["0"], ["29"], ["0"])

    def test_calculate_ja3_empty_lists(self):
        """Empty lists should produce valid hash."""
        ja3_hash = calculate_ja3("771", [], [], [], [])
        assert len(ja3_hash) == 32
        assert ja3_hash.isalnum()

    def test_calculate_ja3_with_none_in_lists(self):
        """None values in lists should be filtered out."""
        ja3_hash = calculate_ja3(
            version="771",
            ciphers=["49195", None, "49196"],
            extensions=[None, "0"],
            curves=["29"],
            point_formats=["0", None],
        )
        assert len(ja3_hash) == 32

    def test_calculate_ja3_with_integers(self):
        """Integer values should be converted to strings."""
        ja3_hash = calculate_ja3(
            version=771,
            ciphers=[49195, 49196],
            extensions=[0, 23],
            curves=[29, 23],
            point_formats=[0],
        )
        assert len(ja3_hash) == 32


class TestLookupJA3:
    def test_lookup_known_malware(self):
        """Lookup known malware JA3."""
        # Cobalt Strike JA3
        result = lookup_ja3("72a589da586844d7f0818ce684948eea")
        assert result is not None
        assert result["malware"] is True
        assert "Cobalt Strike" in result["client"]

    def test_lookup_unknown_hash(self):
        """Unknown hash returns None."""
        result = lookup_ja3("0" * 32)
        assert result is None

    def test_lookup_invalid_hash(self):
        """Invalid hash format returns None."""
        assert lookup_ja3("") is None
        assert lookup_ja3("short") is None
        assert lookup_ja3(None) is None

    def test_lookup_case_insensitive(self):
        """Lookup is case-insensitive."""
        # Use a known hash
        known_hash = "72a589da586844d7f0818ce684948eea"
        upper = lookup_ja3(known_hash.upper())
        lower = lookup_ja3(known_hash.lower())
        assert upper == lower


class TestAnalyzeJA3Results:
    def test_analyze_empty_dataframe(self):
        """Analyze empty DataFrame."""
        result = analyze_ja3_results(pd.DataFrame())
        assert result["total_tls_sessions"] == 0
        assert result["unique_ja3"] == 0
        assert result["malware_detected"] is False

    def test_analyze_with_malware(self):
        """Analyze DataFrame with malware JA3."""
        df = pd.DataFrame(
            [
                {
                    "ja3": "72a589da586844d7f0818ce684948eea",
                    "ja3_client": "Cobalt Strike",
                    "ja3_malware": True,
                    "src": "192.168.1.1",
                    "dst": "10.0.0.1",
                },
                {
                    "ja3": "abcd1234" * 4,
                    "ja3_client": "Unknown",
                    "ja3_malware": False,
                    "src": "192.168.1.2",
                    "dst": "8.8.8.8",
                },
            ]
        )
        result = analyze_ja3_results(df)

        assert result["total_tls_sessions"] == 2
        assert result["malware_detected"] is True
        assert len(result["malware_ja3"]) == 1

    def test_analyze_no_malware(self):
        """Analyze DataFrame without malware."""
        df = pd.DataFrame(
            [
                {"ja3": "abcd1234" * 4, "ja3_client": "Chrome", "ja3_malware": False},
                {"ja3": "efgh5678" * 4, "ja3_client": "Firefox", "ja3_malware": False},
            ]
        )
        result = analyze_ja3_results(df)

        assert result["malware_detected"] is False
        assert len(result["malware_ja3"]) == 0

    def test_analyze_top_clients(self):
        """Analyze returns top clients."""
        df = pd.DataFrame(
            [
                {"ja3": "a" * 32, "ja3_client": "Chrome"},
                {"ja3": "b" * 32, "ja3_client": "Chrome"},
                {"ja3": "c" * 32, "ja3_client": "Firefox"},
            ]
        )
        result = analyze_ja3_results(df)

        assert "Chrome" in result["top_clients"]
        assert result["top_clients"]["Chrome"] == 2


class TestExtractJA3FromZeek:
    def test_extract_missing_file(self, tmp_path):
        """Extract from non-existent file returns empty DataFrame."""
        df = extract_ja3_from_zeek(tmp_path / "nonexistent.log")
        assert df.empty

    def test_extract_json_format(self, tmp_path):
        """Extract from JSON format ssl.log."""
        ssl_log = tmp_path / "ssl.log"
        ssl_log.write_text(
            '{"id.orig_h":"192.168.1.1","id.resp_h":"8.8.8.8",'
            '"id.orig_p":54321,"id.resp_p":443,"ja3":"abcd1234abcd1234abcd1234abcd1234",'
            '"ja3s":"efgh5678efgh5678efgh5678efgh5678","server_name":"example.com"}\n'
        )

        df = extract_ja3_from_zeek(ssl_log)
        assert len(df) == 1
        assert df.iloc[0]["src"] == "192.168.1.1"
        assert df.iloc[0]["ja3"] == "abcd1234abcd1234abcd1234abcd1234"

    def test_extract_no_ja3_data(self, tmp_path):
        """Extract from log without JA3 returns empty DataFrame."""
        ssl_log = tmp_path / "ssl.log"
        ssl_log.write_text('{"id.orig_h":"192.168.1.1","id.resp_h":"8.8.8.8"}\n')

        df = extract_ja3_from_zeek(ssl_log)
        assert df.empty


class TestExtractJA3FromMultipleRuns:
    """Batch mode: JA3 must be combined across every run's own ssl.log."""

    @staticmethod
    def _write_ssl_log(run_dir, src: str, ja3_hash: str) -> str:
        run_dir.mkdir(parents=True, exist_ok=True)
        ssl_log = run_dir / "ssl.log"
        ssl_log.write_text(
            f'{{"id.orig_h":"{src}","id.resp_h":"8.8.8.8",'
            f'"id.orig_p":54321,"id.resp_p":443,"ja3":"{ja3_hash}",'
            f'"ja3s":"efgh5678efgh5678efgh5678efgh5678","server_name":"example.com"}}\n'
        )
        return str(ssl_log)

    def test_combines_ja3_across_runs(self, tmp_path):
        """Two runs with distinct ssl.logs: combined frame covers both files."""
        # Malware JA3 (Cobalt Strike) in the FIRST run — under the old
        # last-ssl.log-wins merge this row would be dropped entirely.
        log1 = self._write_ssl_log(tmp_path / "run1", "192.168.1.1", "72a589da586844d7f0818ce684948eea")
        log2 = self._write_ssl_log(tmp_path / "run2", "192.168.1.2", "abcd1234abcd1234abcd1234abcd1234")

        df, analysis = extract_ja3_from_multiple_runs(
            [
                {"ssl.log": log1, "conn.log": str(tmp_path / "run1" / "conn.log")},
                {"ssl.log": log2},
            ]
        )

        assert len(df) == 2
        assert set(df["src"]) == {"192.168.1.1", "192.168.1.2"}
        assert analysis["total_tls_sessions"] == 2
        assert analysis["unique_ja3"] == 2
        assert analysis["malware_detected"] is True

    def test_drops_duplicate_rows_across_runs(self, tmp_path):
        """Identical TLS rows in two runs are de-duplicated in the combined frame."""
        log1 = self._write_ssl_log(tmp_path / "run1", "192.168.1.1", "abcd1234abcd1234abcd1234abcd1234")
        log2 = self._write_ssl_log(tmp_path / "run2", "192.168.1.1", "abcd1234abcd1234abcd1234abcd1234")

        df, analysis = extract_ja3_from_multiple_runs([{"ssl.log": log1}, {"ssl.log": log2}])

        assert len(df) == 1
        assert analysis["total_tls_sessions"] == 1

    def test_empty_paths_list(self):
        """No runs at all: empty DataFrame and empty analysis dict."""
        df, analysis = extract_ja3_from_multiple_runs([])
        assert df.empty
        assert analysis == {}

    def test_runs_without_ssl_log(self, tmp_path):
        """Runs that produced no ssl.log are skipped; empty result preserved."""
        df, analysis = extract_ja3_from_multiple_runs([{"conn.log": str(tmp_path / "conn.log")}, {}])
        assert df.empty
        assert analysis == {}


class TestKnownFingerprints:
    def test_fingerprints_have_required_fields(self):
        """All fingerprints have required fields."""
        for ja3_hash, info in KNOWN_JA3_FINGERPRINTS.items():
            assert "client" in info
            assert "malware" in info
            assert isinstance(info["malware"], bool)

    def test_malware_fingerprints_present(self):
        """Known malware fingerprints are in database."""
        malware_hashes = [
            "72a589da586844d7f0818ce684948eea",  # Cobalt Strike
            "a0e9f5d64349fb13191bc781f81f42e1",  # Cobalt Strike variant
        ]
        for h in malware_hashes:
            assert h in KNOWN_JA3_FINGERPRINTS
            assert KNOWN_JA3_FINGERPRINTS[h]["malware"] is True
