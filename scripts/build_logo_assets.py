#!/usr/bin/env python3
"""Generate all raster logo + favicon assets from a single Pillow drawing function.

We intentionally don't rasterize the SVG via cairo (dyld headaches on macOS)
— the same design is redrawn with Pillow primitives at each target size so
the output stays pixel-sharp even at 16×16.

Output tree:

    app/static/
      ├── logo.svg            (source-of-truth vector, hand-written)
      ├── logo-256.png        (header logo, light bg)
      ├── logo-dark-256.png   (header logo, dark bg variant)
      ├── favicon-16.png
      ├── favicon-32.png
      ├── favicon-48.png
      ├── favicon-180.png     (apple-touch-icon)
      ├── favicon-512.png     (high-DPI)
      └── favicon.ico         (multi-resolution ICO: 16, 32, 48)

Run:  python3 scripts/build_logo_assets.py
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw

OUT_DIR = Path(__file__).resolve().parent.parent / "app" / "static"
BRAND_DIR = Path(__file__).resolve().parent.parent / "docs" / "brand"

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
NAVY_DEEP = (26, 26, 46, 255)     # #1a1a2e
NAVY_MID = (22, 33, 62, 255)      # #16213e
NAVY_BLUE = (15, 52, 96, 255)     # #0f3460
RED_ALERT = (233, 69, 96, 255)    # #e94560
WHITE = (255, 255, 255, 255)
LIGHT_GRID = (233, 238, 245, 255)  # #e9eef5
DARK_BG = (17, 20, 32, 255)       # dark variant background
TRANSPARENT = (0, 0, 0, 0)


def _draw_logo(size: int, *, dark: bool = False, transparent: bool = True) -> Image.Image:
    """Draw the logo at *size* × *size*. Returns an RGBA image.

    All positions scale proportionally from a 256-unit reference grid.
    Anti-aliasing is achieved by drawing at 4× then downsampling.
    """
    # Render at 4× and downsample with LANCZOS for crisp edges at any size
    scale = 4
    S = size * scale
    unit = S / 256.0  # pixels per SVG unit

    if transparent:
        bg = TRANSPARENT
    else:
        bg = DARK_BG if dark else WHITE
    img = Image.new("RGBA", (S, S), bg)
    d = ImageDraw.Draw(img)

    # Geometry (in SVG units, scaled up)
    def p(v: float) -> float:
        return v * unit

    cx, cy, r = p(100), p(100), p(72)
    ring_w = p(12)

    # --- Magnifying-glass handle (behind lens) ---
    # A rounded rect from (160,160) → (228,182), rotated 45° about center (194, 171).
    # Simpler: draw a thick diagonal line-with-rounded-caps from the lens edge
    # down to the bottom-right.
    handle_start = (
        cx + r * math.cos(math.radians(45)) - p(4) * math.cos(math.radians(45)),
        cy + r * math.sin(math.radians(45)) - p(4) * math.sin(math.radians(45)),
    )
    handle_end = (p(225), p(225))
    # Thick cap: draw two lines — outer (deep navy) + thinner inner (mid navy)
    d.line(
        [handle_start, handle_end],
        fill=NAVY_DEEP,
        width=int(p(22)),
    )
    d.line(
        [handle_start, handle_end],
        fill=NAVY_BLUE,
        width=int(p(10)),
    )

    # --- Lens: white/light disc filling the circle ---
    lens_bg = DARK_BG if dark else WHITE
    d.ellipse(
        [cx - r, cy - r, cx + r, cy + r],
        fill=lens_bg,
    )

    # --- Clipped inner scene — we approximate clipping by drawing then
    # masking via a second pass over the ring.
    inner = Image.new("RGBA", (S, S), TRANSPARENT)
    id_ = ImageDraw.Draw(inner)

    # subtle horizontal baseline
    baseline_color = (40, 50, 80, 255) if dark else LIGHT_GRID
    id_.line([(p(28), cy), (p(172), cy)], fill=baseline_color, width=int(p(2)))

    # Packet waveform (square wave)
    wave_pts = [
        (p(36), p(112)), (p(52), p(112)),
        (p(52), p(82)),  (p(72), p(82)),
        (p(72), p(112)), (p(92), p(112)),
        (p(92), p(68)),  (p(116), p(68)),
        (p(116), p(112)), (p(140), p(112)),
        (p(140), p(88)), (p(164), p(88)),
    ]
    wave_color = (200, 210, 240, 255) if dark else NAVY_MID
    id_.line(wave_pts, fill=wave_color, width=int(p(4)), joint="curve")

    # Packet nodes
    def dot(x: float, y: float, rr: float, color: tuple[int, int, int, int]) -> None:
        id_.ellipse([x - rr, y - rr, x + rr, y + rr], fill=color)

    node_color = (200, 210, 240, 255) if dark else NAVY_MID
    dot(p(52), p(82), p(5), node_color)
    dot(p(92), p(68), p(6), RED_ALERT)  # the "detected" packet
    dot(p(140), p(88), p(5), node_color)

    # Crosshair reticle — short dashes on 4 arms
    reticle_color = (120, 150, 200, 255) if dark else NAVY_BLUE
    reticle_w = int(p(2))

    def dashed(x1: float, y1: float, x2: float, y2: float) -> None:
        dx, dy = x2 - x1, y2 - y1
        length = (dx * dx + dy * dy) ** 0.5
        if length == 0:
            return
        steps = int(length / p(10))
        for i in range(steps):
            if i % 2 == 1:
                continue
            t1 = i / steps
            t2 = (i + 1) / steps
            id_.line(
                [
                    (x1 + dx * t1, y1 + dy * t1),
                    (x1 + dx * t2, y1 + dy * t2),
                ],
                fill=reticle_color,
                width=reticle_w,
            )

    dashed(p(28), cy, p(70), cy)
    dashed(p(130), cy, p(172), cy)
    dashed(cx, p(28), cx, p(70))
    dashed(cx, p(130), cx, p(172))

    # Center marker
    dot(cx, cy, p(3), RED_ALERT)

    # Mask inner scene to the lens circle
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).ellipse(
        [cx - r + int(p(6)), cy - r + int(p(6)), cx + r - int(p(6)), cy + r - int(p(6))],
        fill=255,
    )
    img.paste(inner, (0, 0), mask)

    # --- Lens ring (outer) ---
    d.ellipse(
        [cx - r, cy - r, cx + r, cy + r],
        outline=NAVY_BLUE,
        width=int(ring_w),
    )
    # Inner highlight ring for depth
    d.ellipse(
        [cx - r + int(ring_w / 2), cy - r + int(ring_w / 2),
         cx + r - int(ring_w / 2), cy + r - int(ring_w / 2)],
        outline=NAVY_DEEP,
        width=max(1, int(ring_w / 6)),
    )

    # Downsample to target size for anti-aliasing
    return img.resize((size, size), Image.LANCZOS)


def save_variants() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    BRAND_DIR.mkdir(parents=True, exist_ok=True)

    # Header logos
    for label, dark in (("logo-256.png", False), ("logo-dark-256.png", True)):
        img = _draw_logo(256, dark=dark, transparent=True)
        img.save(OUT_DIR / label, optimize=True)
        print(f"  → {OUT_DIR.relative_to(OUT_DIR.parent.parent)}/{label}")

    # Favicons at common sizes
    favicon_sizes = (16, 32, 48, 180, 512)
    pngs: dict[int, Image.Image] = {}
    for sz in favicon_sizes:
        img = _draw_logo(sz, transparent=True)
        path = OUT_DIR / f"favicon-{sz}.png"
        img.save(path, optimize=True)
        pngs[sz] = img
        print(f"  → {OUT_DIR.relative_to(OUT_DIR.parent.parent)}/favicon-{sz}.png")

    # Multi-resolution .ico (Windows-style, also widely supported)
    ico_path = OUT_DIR / "favicon.ico"
    pngs[48].save(
        ico_path,
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48)],
    )
    print(f"  → {OUT_DIR.relative_to(OUT_DIR.parent.parent)}/favicon.ico")

    # Brand preview for README/docs
    banner = Image.new("RGBA", (900, 320), (248, 250, 253, 255))
    b = ImageDraw.Draw(banner)
    logo_big = _draw_logo(256, transparent=True)
    banner.paste(logo_big, (60, 32), logo_big)

    # Word mark "PCAP Hunter" — simple Pillow text (system font)
    try:
        from PIL import ImageFont

        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 72)
        font_small = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 20)
    except Exception:
        font = ImageFont.load_default()
        font_small = ImageFont.load_default()
    b.text((350, 100), "PCAP Hunter", fill=(26, 26, 46, 255), font=font)
    b.text(
        (350, 185),
        "AI-enhanced threat hunting workbench",
        fill=(80, 90, 110, 255),
        font=font_small,
    )
    banner.convert("RGB").save(BRAND_DIR / "banner.png", optimize=True)
    print(f"  → {BRAND_DIR.relative_to(BRAND_DIR.parent.parent)}/banner.png")


if __name__ == "__main__":
    save_variants()
    print("\n✓ logo assets generated")
