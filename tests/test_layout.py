"""Tests for app/ui/layout.py helpers (theme-aware branding asset selection)."""

from __future__ import annotations

from pathlib import Path

from app.ui.layout import image_data_uri, resolve_logo_path

LIGHT = "logo-256.png"
DARK = "logo-dark-256.png"


def _make_assets(tmp_path, *names):
    for name in names:
        (tmp_path / name).write_bytes(b"\x89PNG")


class TestResolveLogoPath:
    def test_dark_theme_picks_dark_variant(self, tmp_path):
        _make_assets(tmp_path, LIGHT, DARK)
        assert resolve_logo_path(tmp_path, "dark") == tmp_path / DARK

    def test_light_theme_picks_light_variant(self, tmp_path):
        _make_assets(tmp_path, LIGHT, DARK)
        assert resolve_logo_path(tmp_path, "light") == tmp_path / LIGHT

    def test_unknown_theme_defaults_to_light(self, tmp_path):
        _make_assets(tmp_path, LIGHT, DARK)
        assert resolve_logo_path(tmp_path, None) == tmp_path / LIGHT
        assert resolve_logo_path(tmp_path, "") == tmp_path / LIGHT

    def test_theme_type_is_case_insensitive(self, tmp_path):
        _make_assets(tmp_path, LIGHT, DARK)
        assert resolve_logo_path(tmp_path, "Dark") == tmp_path / DARK

    def test_dark_theme_falls_back_to_light_when_dark_missing(self, tmp_path):
        _make_assets(tmp_path, LIGHT)
        assert resolve_logo_path(tmp_path, "dark") == tmp_path / LIGHT

    def test_light_theme_falls_back_to_dark_when_light_missing(self, tmp_path):
        _make_assets(tmp_path, DARK)
        assert resolve_logo_path(tmp_path, "light") == tmp_path / DARK

    def test_returns_none_when_no_assets_exist(self, tmp_path):
        assert resolve_logo_path(tmp_path, "dark") is None
        assert resolve_logo_path(tmp_path, "light") is None


class TestImageDataUri:
    def test_missing_asset_returns_none(self, tmp_path):
        assert image_data_uri(tmp_path / "missing.png") is None
        assert image_data_uri(None) is None

    def test_png_asset_is_encoded_for_header_markup(self, tmp_path):
        asset = tmp_path / "brand.png"
        asset.write_bytes(b"\x89PNG\r\n")

        assert image_data_uri(asset) == "data:image/png;base64,iVBORw0K"


def test_friendly_theme_contains_shell_contract():
    css_path = Path(__file__).parents[1] / "app" / "ui" / "friendly_theme.css"
    css = css_path.read_text(encoding="utf-8")

    assert ".pcap-app-header" in css
    assert '[role="tablist"]' in css
    assert '[role="tab"][aria-selected="true"]' in css
    assert ".pcap-sidebar-health" in css
