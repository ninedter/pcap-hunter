"""Severity color system — the single source of truth for dashboard, charts, and PDF.

Levels (most → least severe): critical, high, medium, low, clean, unknown.
``bg`` is the solid badge/background color, ``fg`` a text color readable on it,
``rgba`` a translucent row-tint for tables.
"""

from __future__ import annotations

SEVERITY_ORDER = ("critical", "high", "medium", "low", "clean", "unknown")

SEVERITY_COLORS: dict[str, dict[str, str]] = {
    "critical": {"bg": "#ff6b6b", "fg": "#ffffff", "rgba": "rgba(255,107,107,0.15)"},
    "high": {"bg": "#ffa94d", "fg": "#1a1a1a", "rgba": "rgba(255,169,77,0.15)"},
    "medium": {"bg": "#ffd43b", "fg": "#1a1a1a", "rgba": "rgba(255,212,59,0.12)"},
    "low": {"bg": "#51cf66", "fg": "#1a1a1a", "rgba": "rgba(81,207,102,0.15)"},
    "clean": {"bg": "#4dabf7", "fg": "#1a1a1a", "rgba": "rgba(77,171,247,0.10)"},
    "unknown": {"bg": "#adb5bd", "fg": "#1a1a1a", "rgba": "rgba(173,181,189,0.18)"},
}


def severity_color(level: str | None, kind: str = "bg") -> str:
    """Return the color for a severity level; unknown levels fall back to 'unknown'."""
    spec = SEVERITY_COLORS.get((level or "unknown").strip().lower(), SEVERITY_COLORS["unknown"])
    return spec.get(kind, spec["bg"])
