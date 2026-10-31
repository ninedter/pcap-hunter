"""Tests for export utilities."""

import csv
import json
from io import StringIO

import pandas as pd
import pytest

from app.utils.export import (
    _MAX_EXPORT_ROWS,
    _flatten_dict,
    _sanitize_csv_value,
    export_dataframe_to_csv,
    export_dataframe_to_json,
    export_to_csv,
    export_to_json,
    generate_export_filename,
)


class TestExportToCSV:
    def test_export_flows_csv(self):
        """Test basic CSV export of flow data."""
        flows = [
            {"src": "192.168.1.100", "dst": "8.8.8.8", "proto": "DNS"},
            {"src": "192.168.1.100", "dst": "1.1.1.1", "proto": "TLS"},
        ]
        result = export_to_csv(flows)
        assert isinstance(result, bytes)

        reader = csv.DictReader(StringIO(result.decode()))
        rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["src"] == "192.168.1.100"
        assert rows[1]["proto"] == "TLS"

    def test_export_empty_data(self):
        """Handle empty input gracefully."""
        result = export_to_csv([])
        assert result == b""

    def test_export_special_chars(self):
        """Handle special characters including unicode."""
        flows = [{"src": "192.168.1.1", "note": "Test \u2605 unicode \u2764"}]
        result = export_to_csv(flows)
        decoded = result.decode("utf-8")
        assert "unicode" in decoded
        assert "\u2605" in decoded

    def test_export_nested_dict(self):
        """Handle nested dictionaries by flattening."""
        data = [{"ip": "8.8.8.8", "osint": {"vt": {"score": 0}, "gn": "benign"}}]
        result = export_to_csv(data)
        decoded = result.decode("utf-8")
        assert "osint_vt_score" in decoded
        assert "osint_gn" in decoded


class TestExportToJSON:
    def test_export_flows_json(self):
        """Test basic JSON export."""
        flows = [
            {"src": "192.168.1.100", "dst": "8.8.8.8"},
            {"src": "192.168.1.100", "dst": "1.1.1.1"},
        ]
        result = export_to_json(flows)
        data = json.loads(result)
        assert len(data) == 2
        assert data[0]["dst"] == "8.8.8.8"

    def test_export_empty_json(self):
        """Handle empty list."""
        result = export_to_json([])
        data = json.loads(result)
        assert data == []

    def test_export_nested_json(self):
        """Preserve nested structure in JSON."""
        data = {"ips": {"8.8.8.8": {"vt": {"score": 0}}}}
        result = export_to_json(data)
        parsed = json.loads(result)
        assert parsed["ips"]["8.8.8.8"]["vt"]["score"] == 0


class TestDataFrameExport:
    def test_dataframe_to_csv(self):
        """Test DataFrame to CSV export."""
        df = pd.DataFrame(
            [
                {"src": "192.168.1.1", "dst": "8.8.8.8"},
                {"src": "192.168.1.2", "dst": "1.1.1.1"},
            ]
        )
        result = export_dataframe_to_csv(df)
        assert b"src,dst" in result
        assert b"192.168.1.1" in result

    def test_dataframe_empty(self):
        """Handle empty DataFrame."""
        df = pd.DataFrame()
        result = export_dataframe_to_csv(df)
        assert result == b""

    def test_dataframe_to_json(self):
        """Test DataFrame to JSON export."""
        df = pd.DataFrame([{"a": 1, "b": 2}])
        result = export_dataframe_to_json(df)
        data = json.loads(result)
        assert len(data) == 1
        assert data[0]["a"] == 1


class TestGenerateFilename:
    def test_generate_filename_csv(self):
        """Test filename generation for CSV."""
        filename = generate_export_filename("flows", "csv")
        assert filename.startswith("flows_")
        assert filename.endswith(".csv")
        assert len(filename) == len("flows_20250129_143052.csv")

    def test_generate_filename_json(self):
        """Test filename generation for JSON."""
        filename = generate_export_filename("osint", "json")
        assert filename.startswith("osint_")
        assert filename.endswith(".json")


class TestFlattenDict:
    def test_flatten_simple(self):
        """Test flattening simple nested dict."""
        d = {"a": {"b": 1, "c": 2}}
        result = _flatten_dict(d)
        assert result == {"a_b": 1, "a_c": 2}

    def test_flatten_with_list(self):
        """Test flattening dict with list values."""
        d = {"ips": ["8.8.8.8", "1.1.1.1"]}
        result = _flatten_dict(d)
        assert result["ips"] == "8.8.8.8; 1.1.1.1"

    def test_flatten_deep(self):
        """Test deep nesting."""
        d = {"a": {"b": {"c": {"d": "value"}}}}
        result = _flatten_dict(d)
        assert result == {"a_b_c_d": "value"}


class TestCSVInjectionProtection:
    """Test CSV injection protection for security."""

    @pytest.mark.parametrize("value", [" =1+1", "\ufeff\t@SUM(A1)", "\x00 +1", "＝1+1", "\rdata"])
    def test_spreadsheet_ignored_prefixes(self, value):
        from app.api.routers.iocs import _csv_safe

        assert _sanitize_csv_value(value) == "'" + value
        assert _csv_safe(value) == "'" + value

    def test_sanitize_formula_equals(self):
        """Sanitize values starting with equals sign."""
        result = _sanitize_csv_value("=cmd|'/c calc'!A1")
        assert result.startswith("'=")

    def test_sanitize_formula_plus(self):
        """Sanitize values starting with plus sign."""
        result = _sanitize_csv_value("+1+2")
        assert result.startswith("'+")

    def test_sanitize_formula_minus(self):
        """Sanitize values starting with minus sign."""
        result = _sanitize_csv_value("-1-2")
        assert result.startswith("'-")

    def test_sanitize_formula_at(self):
        """Sanitize values starting with at sign."""
        result = _sanitize_csv_value("@SUM(A1:A10)")
        assert result.startswith("'@")

    def test_sanitize_normal_value(self):
        """Normal values should not be modified."""
        result = _sanitize_csv_value("192.168.1.1")
        assert result == "192.168.1.1"

    def test_sanitize_none(self):
        """None should become empty string."""
        result = _sanitize_csv_value(None)
        assert result == ""

    def test_sanitize_number(self):
        """Numbers should be converted to string."""
        result = _sanitize_csv_value(12345)
        assert result == "12345"

    def test_export_csv_sanitizes_data(self):
        """Verify export function sanitizes potentially dangerous values."""
        data = [
            {"ip": "192.168.1.1", "payload": "=cmd|'/c calc'!A1"},
            {"ip": "10.0.0.1", "payload": "@SUM(A:A)"},
        ]
        result = export_to_csv(data)
        decoded = result.decode("utf-8")

        # Dangerous formulas should be neutralized with leading quote
        assert "'=" in decoded
        assert "'@" in decoded


class TestExportLimits:
    """Test export size limits for security."""

    def test_export_within_limit(self):
        """Export should work within row limit."""
        data = [{"id": i} for i in range(1000)]
        result = export_to_csv(data)
        assert len(result) > 0

    def test_export_exceeds_limit(self):
        """Export should raise error when exceeding row limit."""
        # Create data exceeding the limit
        data = [{"id": i} for i in range(_MAX_EXPORT_ROWS + 1)]
        with pytest.raises(ValueError, match="exceeds maximum row limit"):
            export_to_csv(data)
