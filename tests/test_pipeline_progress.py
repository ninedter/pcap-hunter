# tests/test_pipeline_progress.py
"""Tests for the headless progress interface."""

from __future__ import annotations

from app.pipeline.progress import CallbackProgress, ProgressEvent


def test_callback_progress_emits_phase_events():
    events: list[ProgressEvent] = []
    progress = CallbackProgress(callback=events.append)

    handle = progress.start_phase("Packet counting")
    handle.set(50, "halfway")
    handle.done("complete")

    assert [e.kind for e in events] == ["phase_start", "phase_set", "phase_done"]
    assert events[0].title == "Packet counting"
    assert events[1].percent == 50
    assert events[1].message == "halfway"
    assert events[2].message == "complete"


def test_callback_progress_overall_pct():
    events: list[ProgressEvent] = []
    progress = CallbackProgress(callback=events.append, total_phases=4)

    progress.start_phase("a").done()
    progress.start_phase("b").done()

    overall_events = [e for e in events if e.kind == "overall"]
    assert overall_events[-1].percent == 50


def test_callback_progress_done_is_idempotent():
    events: list[ProgressEvent] = []
    progress = CallbackProgress(callback=events.append, total_phases=1)
    handle = progress.start_phase("a")
    handle.done()
    handle.done()  # second call should be a no-op
    done_events = [e for e in events if e.kind == "phase_done"]
    assert len(done_events) == 1
    overall_events = [e for e in events if e.kind == "overall"]
    assert len(overall_events) == 1  # _phase_finished only ran once


def test_set_after_done_is_noop():
    events: list[ProgressEvent] = []
    progress = CallbackProgress(callback=events.append)
    handle = progress.start_phase("a")
    handle.done()
    handle.set(75, "stale")
    assert not any(e.kind == "phase_set" and e.message == "stale" for e in events)


def test_zero_total_phases_emits_no_overall():
    events: list[ProgressEvent] = []
    progress = CallbackProgress(callback=events.append, total_phases=0)
    progress.start_phase("a").done()
    assert not any(e.kind == "overall" for e in events)


def test_overall_caps_at_100_when_overshot():
    events: list[ProgressEvent] = []
    progress = CallbackProgress(callback=events.append, total_phases=1)
    progress.start_phase("a").done()
    progress.start_phase("b").done()  # exceeds total_phases
    overall = [e for e in events if e.kind == "overall"]
    assert overall[-1].percent == 100


def test_streamlit_progress_satisfies_protocol():
    """StreamlitProgressAdapter delegates start_phase to the wrapped tracker."""
    from app.pipeline.progress import Progress  # noqa: F401  (protocol used as documentation)
    from app.pipeline.state import StreamlitProgressAdapter, _ThreadSafePhaseHandle

    class _StubTracker:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def next_phase(self, title: str) -> str:
            self.calls.append(title)
            return f"handle:{title}"

    tracker = _StubTracker()
    adapter = StreamlitProgressAdapter(tracker)
    handle = adapter.start_phase("Packet counting")

    assert tracker.calls == ["Packet counting"]
    # The adapter wraps the inner handle in a thread-safe wrapper
    assert isinstance(handle, _ThreadSafePhaseHandle)
    assert handle._inner == "handle:Packet counting"
