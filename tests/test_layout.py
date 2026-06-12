"""Tests for app/ui/layout.py helpers (theme-aware branding asset selection)."""

from __future__ import annotations

from app.ui.layout import resolve_logo_path

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
