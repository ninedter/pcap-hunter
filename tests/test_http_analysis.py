"""Tests for HTTP analysis module."""

from unittest.mock import patch

import pandas as pd
import pytest

from app.pipeline.http_analysis import (
    HTTPRequest,
    analyze_http,
    detect_cleartext_credentials,
    detect_suspicious_ua,
    detect_suspicious_uri,
    parse_http_log,
)


def _req(**overrides) -> HTTPRequest:
    """Build an HTTPRequest with sane defaults, overridden per test."""
    defaults = dict(
        ts=1234567890.0,
        src="192.168.1.10",
        dst="93.184.216.34",
        host="www.example.com",
        uri="/index.html",
        method="GET",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        username="",
        status_code=200,
    )
    defaults.update(overrides)
    return HTTPRequest(**defaults)


class TestParseHTTPLog:
    """Test parsing Zeek http.log DataFrame."""

    def test_empty_dataframe(self):
        df = pd.DataFrame()
        records = parse_http_log(df)
        assert records == []

    def test_basic_parsing_dotted_columns(self):
        df = pd.DataFrame(
            [
                {
                    "ts": "1234567890.0",
                    "id.orig_h": "192.168.1.10",
                    "id.resp_h": "93.184.216.34",
                    "host": "www.example.com",
                    "uri": "/index.html",
                    "method": "GET",
                    "user_agent": "Mozilla/5.0",
                    "username": "-",
                    "password": "-",
                    "status_code": "200",
                }
            ]
        )
        records = parse_http_log(df)
        assert len(records) == 1
        r = records[0]
        assert r.src == "192.168.1.10"
        assert r.dst == "93.184.216.34"
        assert r.host == "www.example.com"
        assert r.uri == "/index.html"
        assert r.method == "GET"
        assert r.user_agent == "Mozilla/5.0"
        assert r.username == ""  # "-" treated as missing
        assert r.status_code == 200

    def test_underscore_column_fallback(self):
        df = pd.DataFrame(
            [
                {
                    "ts": "1234567890.0",
                    "id_orig_h": "10.0.0.5",
                    "id_resp_h": "10.0.0.1",
                    "host": "internal.local",
                    "uri": "/",
                    "method": "GET",
                    "user_agent": "-",
                    "status_code": "-",
                }
            ]
        )
        records = parse_http_log(df)
        assert len(records) == 1
        assert records[0].src == "10.0.0.5"
        assert records[0].dst == "10.0.0.1"
        assert records[0].user_agent == ""
        assert records[0].status_code == 0

    def test_missing_optional_fields_default_empty(self):
        df = pd.DataFrame([{"ts": "1.0", "id.orig_h": "1.2.3.4"}])
        records = parse_http_log(df)
        assert len(records) == 1
        assert records[0].host == ""
        assert records[0].uri == ""
        assert records[0].username == ""


class TestSuspiciousUA:
    """Test suspicious User-Agent detection."""

    def test_missing_ua_with_host_is_suspicious(self):
        req = _req(user_agent="", host="www.example.com")
        reason = detect_suspicious_ua(req)
        assert reason is not None
        assert "user-agent" in reason.lower()

    def test_missing_ua_without_host_is_not_flagged(self):
        req = _req(user_agent="", host="")
        assert detect_suspicious_ua(req) is None

    @pytest.mark.parametrize(
        "ua",
        [
            "python-requests/2.28.0",
            "curl/7.79.1",
            "Wget/1.21",
            "PowerShell/7.2",
            "Go-http-client/1.1",
            "Nmap Scripting Engine",
            "sqlmap/1.6",
        ],
    )
    def test_known_tool_ua_is_suspicious(self, ua):
        req = _req(user_agent=ua)
        reason = detect_suspicious_ua(req)
        assert reason is not None

    def test_normal_browser_ua_is_not_flagged(self):
        req = _req(user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15")
        assert detect_suspicious_ua(req) is None


class TestCleartextCredentials:
    """Test cleartext credential detection."""

    def test_username_present_is_flagged(self):
        req = _req(username="admin", uri="/login")
        cred = detect_cleartext_credentials(req)
        assert cred == {"host": req.host, "uri": "/login", "username": "admin"}

    def test_username_missing_is_not_flagged(self):
        req = _req(username="")
        assert detect_cleartext_credentials(req) is None

    def test_password_value_never_emitted(self):
        req = _req(username="admin")
        cred = detect_cleartext_credentials(req)
        assert "password" not in cred


class TestSuspiciousURI:
    """Test suspicious URI detection."""

    @pytest.mark.parametrize("ext", [".exe", ".dll", ".ps1", ".scr", ".bin"])
    def test_risky_extension_is_flagged(self, ext):
        req = _req(uri=f"/downloads/payload{ext}")
        reason = detect_suspicious_uri(req)
        assert reason is not None

    def test_long_uri_is_flagged(self):
        req = _req(uri="/path?" + "a" * 600)
        reason = detect_suspicious_uri(req)
        assert reason is not None
        assert "long" in reason.lower()

    def test_raw_ip_host_file_download_is_flagged(self):
        req = _req(host="203.0.113.5", uri="/payload.dll")
        reason = detect_suspicious_uri(req)
        assert reason is not None

    def test_clean_uri_is_not_flagged(self):
        req = _req(uri="/index.html")
        assert detect_suspicious_uri(req) is None

    def test_empty_uri_is_not_flagged(self):
        req = _req(uri="")
        assert detect_suspicious_uri(req) is None


class TestAnalyzeHTTP:
    """Test comprehensive HTTP analysis."""

    def test_empty_zeek_tables_is_skipped(self):
        result = analyze_http({})
        assert result == {"skipped": True}

    def test_empty_http_log_is_error(self):
        result = analyze_http({"http.log": pd.DataFrame()})
        assert result.get("error") == "No HTTP log data"
        assert result.get("records") == 0

    def test_basic_analysis_all_heuristics(self):
        df = pd.DataFrame(
            [
                {
                    "ts": "1.0",
                    "id.orig_h": "192.168.1.10",
                    "id.resp_h": "93.184.216.34",
                    "host": "www.example.com",
                    "uri": "/index.html",
                    "method": "GET",
                    "user_agent": "Mozilla/5.0",
                    "username": "-",
                    "status_code": "200",
                },
                {
                    "ts": "2.0",
                    "id.orig_h": "192.168.1.11",
                    "id.resp_h": "93.184.216.34",
                    "host": "www.example.com",
                    "uri": "/api/data",
                    "method": "GET",
                    "user_agent": "-",
                    "username": "-",
                    "status_code": "200",
                },
                {
                    "ts": "3.0",
                    "id.orig_h": "192.168.1.12",
                    "id.resp_h": "198.51.100.9",
                    "host": "cdn.example.net",
                    "uri": "/pkg/tool.tar.gz",
                    "method": "GET",
                    "user_agent": "python-requests/2.28.0",
                    "username": "-",
                    "status_code": "200",
                },
                {
                    "ts": "4.0",
                    "id.orig_h": "192.168.1.13",
                    "id.resp_h": "10.0.0.5",
                    "host": "10.0.0.5",
                    "uri": "/admin",
                    "method": "POST",
                    "user_agent": "Mozilla/5.0",
                    "username": "admin",
                    "password": "hunter2",
                    "status_code": "401",
                },
                {
                    "ts": "5.0",
                    "id.orig_h": "192.168.1.14",
                    "id.resp_h": "198.51.100.10",
                    "host": "files.example.org",
                    "uri": "/downloads/update.exe",
                    "method": "GET",
                    "user_agent": "Mozilla/5.0",
                    "username": "-",
                    "status_code": "200",
                },
                {
                    "ts": "6.0",
                    "id.orig_h": "192.168.1.15",
                    "id.resp_h": "203.0.113.5",
                    "host": "203.0.113.5",
                    "uri": "/malware.dll",
                    "method": "GET",
                    "user_agent": "Mozilla/5.0",
                    "username": "-",
                    "status_code": "200",
                },
                {
                    "ts": "7.0",
                    "id.orig_h": "192.168.1.16",
                    "id.resp_h": "198.51.100.11",
                    "host": "files.example.org",
                    "uri": "/q?" + "x" * 600,
                    "method": "GET",
                    "user_agent": "Mozilla/5.0",
                    "username": "-",
                    "status_code": "200",
                },
            ]
        )
        result = analyze_http({"http.log": df})

        assert result["total_requests"] == 7
        assert result["unique_hosts"] == 5
        assert result["methods"] == {"GET": 6, "POST": 1}
        assert result["status_codes"]["200"] == 6
        assert result["status_codes"]["401"] == 1

        assert result["alerts"]["suspicious_ua_count"] == 2  # missing UA + python-requests
        assert result["alerts"]["cleartext_cred_count"] == 1
        assert result["alerts"]["suspicious_uri_count"] == 3  # .exe, .dll(+raw-ip), long query

        assert len(result["suspicious_user_agents"]) == 2
        assert len(result["cleartext_credentials"]) == 1
        assert result["cleartext_credentials"][0] == {"host": "10.0.0.5", "uri": "/admin", "username": "admin"}
        # Password must never be emitted even though the log carried one.
        assert all("password" not in c for c in result["cleartext_credentials"])
        assert len(result["suspicious_uris"]) == 3

    def test_clean_traffic_yields_empty_alerts(self):
        df = pd.DataFrame(
            [
                {
                    "ts": "1.0",
                    "id.orig_h": "192.168.1.10",
                    "id.resp_h": "93.184.216.34",
                    "host": "www.example.com",
                    "uri": "/index.html",
                    "method": "GET",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                    "username": "-",
                    "status_code": "200",
                },
                {
                    "ts": "2.0",
                    "id.orig_h": "192.168.1.11",
                    "id.resp_h": "93.184.216.34",
                    "host": "www.example.com",
                    "uri": "/style.css",
                    "method": "GET",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                    "username": "-",
                    "status_code": "200",
                },
            ]
        )
        result = analyze_http({"http.log": df})

        assert result["total_requests"] == 2
        assert result["suspicious_user_agents"] == []
        assert result["cleartext_credentials"] == []
        assert result["suspicious_uris"] == []
        assert result["alerts"] == {
            "suspicious_ua_count": 0,
            "cleartext_cred_count": 0,
            "suspicious_uri_count": 0,
        }

    def test_http_log_path_used_over_capped_table(self):
        """When http_log_path is given, the full uncapped log wins over zeek_tables."""
        capped_df = pd.DataFrame(
            [
                {
                    "ts": "1.0",
                    "id.orig_h": "192.168.1.10",
                    "id.resp_h": "93.184.216.34",
                    "host": "capped.example.com",
                    "uri": "/",
                    "method": "GET",
                    "user_agent": "Mozilla/5.0",
                    "status_code": "200",
                }
            ]
        )
        full_df = pd.DataFrame(
            [
                {
                    "ts": "1.0",
                    "id.orig_h": "192.168.1.10",
                    "id.resp_h": "93.184.216.34",
                    "host": "full.example.com",
                    "uri": "/",
                    "method": "GET",
                    "user_agent": "Mozilla/5.0",
                    "status_code": "200",
                },
                {
                    "ts": "2.0",
                    "id.orig_h": "192.168.1.11",
                    "id.resp_h": "93.184.216.34",
                    "host": "full.example.com",
                    "uri": "/extra",
                    "method": "GET",
                    "user_agent": "Mozilla/5.0",
                    "status_code": "200",
                },
            ]
        )
        with patch("app.pipeline.http_analysis.load_zeek_any", return_value=full_df) as mock_load:
            result = analyze_http({"http.log": capped_df}, http_log_path="/fake/path/http.log")

        mock_load.assert_called_once_with("/fake/path/http.log")
        assert result["total_requests"] == 2
        assert result["unique_hosts"] == 1

    def test_http_log_path_load_failure_falls_back_to_zeek_tables(self):
        df = pd.DataFrame(
            [
                {
                    "ts": "1.0",
                    "id.orig_h": "192.168.1.10",
                    "id.resp_h": "93.184.216.34",
                    "host": "www.example.com",
                    "uri": "/",
                    "method": "GET",
                    "user_agent": "Mozilla/5.0",
                    "status_code": "200",
                }
            ]
        )
        with patch("app.pipeline.http_analysis.load_zeek_any", side_effect=OSError("boom")):
            result = analyze_http({"http.log": df}, http_log_path="/does/not/exist/http.log")

        assert result["total_requests"] == 1
