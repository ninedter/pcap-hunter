"""Single source of truth for severity colors across dashboard, charts, and PDF."""

import re

from app.ui.colors import SEVERITY_COLORS, SEVERITY_ORDER, severity_color


class TestSeverityColors:
    def test_all_levels_present_with_complete_specs(self):
        for level in ("critical", "high", "medium", "low", "clean", "unknown"):
            spec = SEVERITY_COLORS[level]
            assert re.fullmatch(r"#[0-9a-fA-F]{6}", spec["bg"])
            assert re.fullmatch(r"#[0-9a-fA-F]{6}", spec["fg"])
            assert spec["rgba"].startswith("rgba(")

    def test_order_is_most_severe_first(self):
        assert SEVERITY_ORDER[0] == "critical"
        assert SEVERITY_ORDER[-1] == "unknown"

    def test_lookup_is_case_insensitive_with_unknown_fallback(self):
        assert severity_color("CRITICAL") == SEVERITY_COLORS["critical"]["bg"]
        assert severity_color("nonsense") == SEVERITY_COLORS["unknown"]["bg"]
        assert severity_color(None) == SEVERITY_COLORS["unknown"]["bg"]
        assert severity_color("HIGH", kind="rgba") == SEVERITY_COLORS["high"]["rgba"]
