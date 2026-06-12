"""Regression tests for the generated logo assets in app/static/.

Guards against the two generator bugs that shipped a "cut off" header icon:
  1. paste()-with-mask erasing the lens disc (transparent lens interior)
  2. PIL ellipse(outline=, width=) moiré leaving the ring patchy/translucent

If these fail after editing scripts/build_logo_assets.py, regenerate with:
    python3 scripts/build_logo_assets.py
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest
from PIL import Image

STATIC_DIR = Path(__file__).resolve().parent.parent / "app" / "static"

RING_RADIUS = 72  # SVG-space stroke centerline
# Points inside the lens that no waveform/reticle/dot stroke touches
LENS_SAMPLES = ((60, 130), (130, 90), (80, 135))
MIN_RING_ALPHA = 250

VARIANTS = [("logo-256.png", False), ("logo-dark-256.png", True)]


def _load(name: str):
    return Image.open(STATIC_DIR / name).convert("RGBA").load()


def _ring_point(deg: float) -> tuple[int, int]:
    x = round(100 + RING_RADIUS * math.cos(math.radians(deg)))
    y = round(100 + RING_RADIUS * math.sin(math.radians(deg)))
    return x, y


class TestLogoAssets:
    @pytest.mark.parametrize(("name", "dark"), VARIANTS)
    def test_lens_disc_is_opaque(self, name, dark):
        px = _load(name)
        for x, y in LENS_SAMPLES:
            r, g, b, a = px[x, y]
            assert a == 255, f"{name}: lens interior ({x},{y}) not opaque — alpha={a}"
            if not dark:
                assert (r, g, b) >= (200, 200, 200), (
                    f"{name}: light lens interior ({x},{y}) not white-ish — rgb=({r},{g},{b})"
                )

    @pytest.mark.parametrize(("name", "dark"), VARIANTS)
    def test_ring_is_solid_at_every_angle(self, name, dark):
        px = _load(name)
        for deg in range(0, 360, 45):
            x, y = _ring_point(deg)
            a = px[x, y][3]
            assert a >= MIN_RING_ALPHA, f"{name}: ring at {deg}° ({x},{y}) translucent — alpha={a}"

    def test_dark_variant_strokes_contrast_with_dark_background(self):
        px = _load("logo-dark-256.png")
        x, y = _ring_point(270)
        r, g, b, _ = px[x, y]
        assert (r + g + b) / 3 >= 70, f"dark-theme ring too dark for a dark page — rgb=({r},{g},{b})"
