"""Render Plotly figures to base64-encoded PNG images for PDF embedding.

WeasyPrint can embed ``<img src="data:image/png;base64,..." />`` directly,
which lets us include the dashboard's charts in the PDF report without
needing a browser. The rendering itself is done by ``kaleido``, a
pure-Python Plotly dependency.

If ``kaleido`` is missing, the helpers return ``None`` so callers can
render the PDF without charts rather than crashing.
"""

from __future__ import annotations

import base64
from functools import lru_cache
from typing import TYPE_CHECKING

from app.utils.logger import get_logger

if TYPE_CHECKING:
    import plotly.graph_objects as go

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Availability check — done once at import time
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _kaleido_available() -> bool:
    """Return True when kaleido is importable and usable."""
    try:
        import kaleido  # noqa: F401
    except ImportError:
        return False
    # Plotly uses kaleido via .to_image(); verify that path actually works.
    # We don't pass engine="kaleido" explicitly — that argument is being
    # removed in kaleido 1.x and kaleido is the default renderer anyway.
    try:
        import plotly.graph_objects as _go

        fig = _go.Figure()
        fig.to_image(format="png", width=10, height=10)
        return True
    except Exception as e:  # pragma: no cover - environmental
        logger.warning("kaleido unusable: %s", e)
        return False


def charts_available() -> bool:
    """Report whether chart-to-image rendering is available in this env."""
    return _kaleido_available()


# ---------------------------------------------------------------------------
# Figure → base64 PNG
# ---------------------------------------------------------------------------


def figure_to_data_uri(
    fig: "go.Figure | None",
    *,
    width: int = 900,
    height: int = 450,
    scale: float = 2.0,
) -> str | None:
    """Render a Plotly figure to a ``data:image/png;base64,...`` URI.

    Args:
        fig: The Plotly figure to render. ``None`` is tolerated and yields
            ``None`` (caller can skip the chart).
        width: Image width in pixels.
        height: Image height in pixels.
        scale: Device pixel ratio (2.0 keeps the image crisp in PDFs).

    Returns:
        A ``data:image/png;base64,<payload>`` string, or ``None`` if
        kaleido is unavailable or rendering fails.
    """
    if fig is None or not _kaleido_available():
        return None
    try:
        png_bytes = fig.to_image(format="png", width=width, height=height, scale=scale)
        b64 = base64.b64encode(png_bytes).decode("ascii")
        return f"data:image/png;base64,{b64}"
    except Exception as e:
        logger.warning("Chart render failed (%s): %s", type(fig).__name__, e)
        return None


def figure_to_img_tag(
    fig: "go.Figure | None",
    *,
    alt: str = "",
    width: int = 900,
    height: int = 450,
    scale: float = 2.0,
    css_class: str = "report-chart",
) -> str:
    """Convenience wrapper: return a full ``<img>`` tag or empty string.

    Useful inside PDF render methods so they don't each have to construct
    the tag. If rendering fails, returns an empty string so the caller
    can append safely without conditional logic.
    """
    uri = figure_to_data_uri(fig, width=width, height=height, scale=scale)
    if not uri:
        return ""
    import html as _html

    alt_attr = _html.escape(alt)
    return f'<img class="{css_class}" alt="{alt_attr}" src="{uri}" />'
