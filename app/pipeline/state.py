from __future__ import annotations

import logging
import pathlib
import threading
import time
from typing import Any

import streamlit as st

from app.utils.common import make_slug

try:
    # Stable location across Streamlit 1.3x–1.5x. Without attaching this
    # context, widget updates from worker threads are silently dropped
    # ("missing ScriptRunContext") and progress bars never move.
    from streamlit.runtime.scriptrunner import add_script_run_ctx, get_script_run_ctx
except ImportError:  # pragma: no cover — layout changed in some future Streamlit
    add_script_run_ctx = None  # type: ignore[assignment]
    get_script_run_ctx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


class PipelineTimer:
    """Track timing for each pipeline stage for performance diagnostics.

    Usage::

        timer = PipelineTimer()
        with timer.stage("PyShark"):
            parse_pcap(...)
        with timer.stage("Zeek"):
            run_zeek(...)
        print(timer.summary())
    """

    def __init__(self):
        self._stages: list[dict[str, Any]] = []
        self._start = time.time()

    class _StageContext:
        def __init__(self, timer: "PipelineTimer", name: str):
            self._timer = timer
            self._name = name
            self._start = 0.0

        def __enter__(self):
            self._start = time.time()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            elapsed = time.time() - self._start
            self._timer._stages.append(
                {
                    "name": self._name,
                    "elapsed": round(elapsed, 2),
                    "error": str(exc_val) if exc_val else None,
                }
            )
            logger.info(
                "Pipeline stage '%s' completed in %.2fs%s",
                self._name,
                elapsed,
                f" (ERROR: {exc_val})" if exc_val else "",
            )
            return False  # Don't suppress exceptions

    def stage(self, name: str) -> _StageContext:
        """Return a context manager that times a named stage."""
        return self._StageContext(self, name)

    @property
    def total_elapsed(self) -> float:
        return round(time.time() - self._start, 2)

    def summary(self) -> dict[str, Any]:
        """Return timing summary as a dict."""
        return {
            "total_seconds": self.total_elapsed,
            "stages": list(self._stages),
            "slowest": max(self._stages, key=lambda s: s["elapsed"])["name"] if self._stages else None,
            "errors": [s["name"] for s in self._stages if s.get("error")],
        }

    def summary_text(self) -> str:
        """Return human-readable timing summary."""
        lines = [f"Pipeline completed in {self.total_elapsed}s:"]
        for s in self._stages:
            status = "❌" if s.get("error") else "✅"
            lines.append(f"  {status} {s['name']}: {s['elapsed']}s")
        if self._stages:
            slowest = max(self._stages, key=lambda s: s["elapsed"])
            lines.append(f"  ⏱️ Slowest: {slowest['name']} ({slowest['elapsed']}s)")
        return "\n".join(lines)


def ss_init(key, default):
    if key not in st.session_state:
        st.session_state[key] = default
    return st.session_state[key]


def reset_run_state(phase_titles):
    st.session_state["run_active"] = True
    st.session_state["run_started_at"] = time.time()
    st.session_state["pipeline_timer"] = PipelineTimer()
    for t in phase_titles:
        slug = make_slug(t)
        st.session_state[f"skip_{slug}"] = False
        st.session_state[f"done_{slug}"] = False


def is_run_active() -> bool:
    return st.session_state.get("run_active", False)


def end_run():
    st.session_state["run_active"] = False
    # Log pipeline timing summary
    timer = st.session_state.get("pipeline_timer")
    if timer and isinstance(timer, PipelineTimer):
        logger.info("Pipeline timing:\n%s", timer.summary_text())


class PhaseTracker:
    def __init__(self, total_phases: int, progress_container: st.delta_generator.DeltaGenerator | None = None):
        self.total_phases = max(total_phases, 1)
        self.done_phases = 0
        self._pc = progress_container or st
        with self._pc:
            self.overall_bar = st.progress(0)
            self.overall_text = st.empty()

    def update_overall(self, label: str = ""):
        pct = int(min(self.done_phases / self.total_phases, 1.0) * 100)
        self.overall_bar.progress(pct)
        if label:
            self.overall_text.write(f"Overall progress: {pct}% — {label}")

    def next_phase(self, title: str):
        with self._pc:
            st.caption(title)
            # Safe CSS hook wrapper (no .classes() calls)
            st.markdown('<div class="phase-row">', unsafe_allow_html=True)
            cols = st.columns([5, 1.1])
            with cols[0]:
                bar = st.progress(0)
                text = st.empty()
            with cols[1]:
                slug = make_slug(title)
                skip_key = f"skip_{slug}"
                ss_init(skip_key, False)
                done_key = f"done_{slug}"
                ss_init(done_key, False)
                st.button(
                    "Skip",
                    key=f"btn_{slug}",
                    width="stretch",
                    on_click=lambda: st.session_state.__setitem__(skip_key, True),
                )
            st.markdown("</div>", unsafe_allow_html=True)
        return PhaseHandle(self, bar, text, title, slug, skip_key, done_key)

    def mark_phase_done(self, phase_title: str, skipped: bool = False):
        self.done_phases += 1
        self.update_overall(("Skipped" if skipped else "Completed") + f": {phase_title}")


class PhaseHandle:
    def __init__(self, tracker, bar, text, title, slug, skip_key, done_key):
        self.tracker = tracker
        self.bar = bar
        self.text = text
        self.title = title
        self.slug = slug
        self.skip_key = skip_key
        self.done_key = done_key
        self._last_pct = -1

    def should_skip(self) -> bool:
        return st.session_state.get(self.skip_key, False)

    def is_done(self) -> bool:
        return st.session_state.get(self.done_key, False)

    def _set_done_flag(self):
        st.session_state[self.done_key] = True

    def set(self, pct: float, msg: str = ""):
        if self.is_done():
            return
        if self.should_skip():
            self.text.write("Skipping on user request…")
            return
        pct = int(max(0, min(100, pct)))
        if pct != self._last_pct:
            self.bar.progress(pct)
            self._last_pct = pct
        if msg:
            self.text.write(msg)

    def done(self, msg: str = "Done"):
        if not self.is_done():
            skipped = False
            if not self.should_skip():
                self.set(100, msg)
            else:
                skipped = True
                self.text.write("Skipped by user.")
                self.bar.progress(100)
            self._set_done_flag()
            self.tracker.mark_phase_done(self.title, skipped=skipped)


class BatchPhaseTracker:
    """Progress tracker for multi-file batch processing.

    Wraps per-file ``PhaseTracker`` instances with an overall file-level
    progress bar so users see "File 2/5: malware.pcap" alongside the
    per-phase detail.
    """

    def __init__(self, total_files: int, phases_per_file: int, container):
        self.total_files = max(total_files, 1)
        self.phases_per_file = max(phases_per_file, 1)
        self.current_file = 0
        self._container = container
        with container:
            st.markdown("#### Batch Progress")
            self.file_bar = st.progress(0)
            self.file_text = st.empty()
            st.markdown("---")

    def start_file(self, filename: str) -> PhaseTracker:
        """Begin tracking a new file and return a PhaseTracker for its stages."""
        self.current_file += 1
        pct = int((self.current_file - 1) / self.total_files * 100)
        self.file_bar.progress(pct)
        self.file_text.write(f"File {self.current_file}/{self.total_files}: **{pathlib.Path(filename).name}**")
        return PhaseTracker(self.phases_per_file, progress_container=self._container)

    def finish_file(self):
        """Mark the current file as fully processed."""
        pct = int(self.current_file / self.total_files * 100)
        self.file_bar.progress(pct)

    def finish_all(self, msg: str = "Batch complete."):
        """Mark all files as done."""
        self.file_bar.progress(100)
        self.file_text.write(msg)


class _ThreadSafePhaseHandle:
    """Wraps a Streamlit PhaseHandle to be safe for use from worker threads.

    The pipeline runner executes stages in ThreadPoolExecutor workers (PyShark+Zeek,
    then the DNS/TLS/beacon/carve fan-out). Streamlit widget updates require the
    ScriptRunContext, which only the main script thread has by default — without
    it, updates from worker threads are dropped and the progress bars freeze while
    the analysis runs invisibly.

    The handle is always created on the main thread (see StreamlitProgressAdapter),
    so we capture the context here and re-attach it to whichever worker thread
    later calls ``set()``/``done()``. Exceptions are still swallowed so a UI
    failure can never abort an analysis stage.
    """

    def __init__(self, inner: PhaseHandle) -> None:
        self._inner = inner
        self._ctx = get_script_run_ctx() if get_script_run_ctx is not None else None

    def _attach_ctx(self) -> None:
        """Attach the captured ScriptRunContext to the calling thread (idempotent)."""
        if self._ctx is not None and add_script_run_ctx is not None:
            add_script_run_ctx(threading.current_thread(), self._ctx)

    def set(self, pct: float, msg: str = "") -> None:
        try:
            self._attach_ctx()
            self._inner.set(pct, msg)
        except Exception:
            pass  # UI update failed from thread — analysis continues

    def done(self, msg: str = "Done") -> None:
        try:
            self._attach_ctx()
            self._inner.done(msg)
        except Exception:
            pass

    def should_skip(self) -> bool:
        try:
            self._attach_ctx()
            return self._inner.should_skip()
        except Exception:
            return False  # default: don't skip

    def is_done(self) -> bool:
        try:
            self._attach_ctx()
            return self._inner.is_done()
        except Exception:
            return False


class StreamlitProgressAdapter:
    """Adapts an existing PhaseTracker (Streamlit) to the headless Progress protocol.

    Allows pipeline orchestration code to call ``progress.start_phase()`` regardless
    of whether it's driven by the UI or by the API worker.

    Phase handles are wrapped in ``_ThreadSafePhaseHandle`` so they can be safely
    passed to worker threads (e.g. the PyShark+Zeek ThreadPoolExecutor).
    """

    def __init__(self, tracker: PhaseTracker) -> None:
        self._tracker = tracker

    def start_phase(self, title: str) -> _ThreadSafePhaseHandle:
        inner = self._tracker.next_phase(title)
        return _ThreadSafePhaseHandle(inner)
