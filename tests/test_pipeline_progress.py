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


def test_thread_safe_handle_attaches_script_run_ctx_to_worker_threads(monkeypatch):
    """Worker-thread set()/done() must re-attach the main thread's ScriptRunContext.

    Without this, Streamlit drops widget updates from pipeline worker threads
    ("missing ScriptRunContext") and the progress bars freeze at 0% while the
    analysis runs invisibly — the exact symptom seen on Streamlit 1.58.
    """
    import threading

    from app.pipeline import state as state_mod

    sentinel_ctx = object()
    attached: list[tuple[threading.Thread, object]] = []

    monkeypatch.setattr(state_mod, "get_script_run_ctx", lambda: sentinel_ctx)
    monkeypatch.setattr(state_mod, "add_script_run_ctx", lambda th, ctx: attached.append((th, ctx)))

    class _StubInner:
        def __init__(self) -> None:
            self.calls: list[tuple] = []

        def set(self, pct, msg=""):
            self.calls.append(("set", pct, msg))

        def done(self, msg="Done"):
            self.calls.append(("done", msg))

    inner = _StubInner()
    handle = state_mod._ThreadSafePhaseHandle(inner)  # created on the "main" thread

    worker = threading.Thread(target=lambda: (handle.set(50, "halfway"), handle.done("ok")))
    worker.start()
    worker.join()

    assert ("set", 50, "halfway") in inner.calls
    assert ("done", "ok") in inner.calls
    # The captured context was attached to the worker thread for both calls.
    assert attached and all(ctx is sentinel_ctx for _, ctx in attached)
    assert all(th is worker for th, _ in attached)


def test_thread_safe_handle_tolerates_missing_ctx(monkeypatch):
    """Headless contexts (API worker, bare pytest) have no ScriptRunContext — the
    handle must degrade to plain pass-through without raising."""
    from app.pipeline import state as state_mod

    monkeypatch.setattr(state_mod, "get_script_run_ctx", lambda: None)

    class _StubInner:
        def __init__(self) -> None:
            self.calls: list[tuple] = []

        def set(self, pct, msg=""):
            self.calls.append(("set", pct, msg))

    inner = _StubInner()
    handle = state_mod._ThreadSafePhaseHandle(inner)
    handle.set(10, "ok")
    assert inner.calls == [("set", 10, "ok")]
