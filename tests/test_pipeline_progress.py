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
