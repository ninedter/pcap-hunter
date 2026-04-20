"""Tests for the Plotly-to-PNG chart helper used by the PDF report."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import plotly.graph_objects as go

from app.reports import chart_images


def _fresh_cache() -> None:
    """Clear the lru_cache so availability check is re-evaluated per test."""
    chart_images._kaleido_available.cache_clear()


class TestKaleidoAvailability:
    def test_charts_available_when_kaleido_missing(self):
        _fresh_cache()
        with patch.dict("sys.modules", {"kaleido": None}):
            # With kaleido patched to None, the import inside _kaleido_available
            # should raise ImportError and return False.
            with patch.object(chart_images, "_kaleido_available", return_value=False):
                assert chart_images.charts_available() is False

    def test_charts_available_when_kaleido_present(self):
        _fresh_cache()
        with patch.object(chart_images, "_kaleido_available", return_value=True):
            assert chart_images.charts_available() is True


class TestFigureToDataUri:
    def test_none_figure_returns_none(self):
        _fresh_cache()
        assert chart_images.figure_to_data_uri(None) is None

    def test_returns_none_when_kaleido_unavailable(self):
        _fresh_cache()
        fig = go.Figure()
        with patch.object(chart_images, "_kaleido_available", return_value=False):
            assert chart_images.figure_to_data_uri(fig) is None

    def test_returns_data_uri_when_successful(self):
        _fresh_cache()
        fig = MagicMock(spec=go.Figure)
        fig.to_image.return_value = b"\x89PNG\r\n\x1a\nfakebytes"
        with patch.object(chart_images, "_kaleido_available", return_value=True):
            uri = chart_images.figure_to_data_uri(fig, width=100, height=50)
        assert uri is not None
        assert uri.startswith("data:image/png;base64,")
        # Verify the base64 content round-trips back to our bytes
        import base64

        payload = uri.split(",", 1)[1]
        assert base64.b64decode(payload) == b"\x89PNG\r\n\x1a\nfakebytes"
        # Verify width/height/scale were forwarded
        fig.to_image.assert_called_once()
        kwargs = fig.to_image.call_args.kwargs
        assert kwargs.get("width") == 100
        assert kwargs.get("height") == 50
        assert kwargs.get("format") == "png"

    def test_returns_none_on_render_failure(self):
        _fresh_cache()
        fig = MagicMock(spec=go.Figure)
        fig.to_image.side_effect = RuntimeError("kaleido crashed")
        with patch.object(chart_images, "_kaleido_available", return_value=True):
            assert chart_images.figure_to_data_uri(fig) is None


class TestFigureToImgTag:
    def test_empty_string_when_uri_missing(self):
        _fresh_cache()
        with patch.object(chart_images, "figure_to_data_uri", return_value=None):
            assert chart_images.figure_to_img_tag(None, alt="x") == ""

    def test_escapes_alt_text(self):
        _fresh_cache()
        with patch.object(chart_images, "figure_to_data_uri", return_value="data:image/png;base64,AAA="):
            tag = chart_images.figure_to_img_tag(MagicMock(), alt='"<x>')
        assert 'alt="&quot;&lt;x&gt;"' in tag
        assert 'src="data:image/png;base64,AAA="' in tag

    def test_uses_default_css_class(self):
        _fresh_cache()
        with patch.object(chart_images, "figure_to_data_uri", return_value="data:image/png;base64,AAA="):
            tag = chart_images.figure_to_img_tag(MagicMock())
        assert 'class="report-chart"' in tag

    def test_custom_css_class(self):
        _fresh_cache()
        with patch.object(chart_images, "figure_to_data_uri", return_value="data:image/png;base64,AAA="):
            tag = chart_images.figure_to_img_tag(MagicMock(), css_class="my-chart")
        assert 'class="my-chart"' in tag
