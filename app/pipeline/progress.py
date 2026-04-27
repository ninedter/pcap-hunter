# app/pipeline/progress.py
"""Headless progress reporting for the pipeline.

The Streamlit UI uses ``app/pipeline/state.PhaseTracker`` (which writes to
``st.session_state``). The API worker uses ``CallbackProgress`` which forwards
events to a plain callable. The pipeline orchestration code accepts either
via the ``Progress`` protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Protocol

EventKind = Literal["phase_start", "phase_set", "phase_done", "overall"]


@dataclass
class ProgressEvent:
    kind: EventKind
    title: str = ""
    percent: int = 0
    message: str = ""


class PhaseHandle(Protocol):
    def set(self, percent: int, message: str = "") -> None: ...
    def done(self, message: str = "Done") -> None: ...
    def should_skip(self) -> bool: ...


class Progress(Protocol):
    def start_phase(self, title: str) -> PhaseHandle: ...


class _CallbackPhaseHandle:
    def __init__(self, parent: "CallbackProgress", title: str) -> None:
        self._parent = parent
        self._title = title
        self._done = False

    def set(self, percent: int, message: str = "") -> None:
        if self._done:
            return
        self._parent._emit(ProgressEvent("phase_set", self._title, int(percent), message))

    def done(self, message: str = "Done") -> None:
        if self._done:
            return
        self._done = True
        self._parent._emit(ProgressEvent("phase_done", self._title, 100, message))
        self._parent._phase_finished()

    def should_skip(self) -> bool:
        return False


class CallbackProgress:
    """Headless progress reporter that forwards events to a callable."""

    def __init__(self, callback: Callable[[ProgressEvent], None], total_phases: int = 0) -> None:
        self._callback = callback
        self._total = max(total_phases, 0)
        self._done = 0

    def start_phase(self, title: str) -> _CallbackPhaseHandle:
        self._emit(ProgressEvent("phase_start", title=title))
        return _CallbackPhaseHandle(self, title)

    def _emit(self, event: ProgressEvent) -> None:
        self._callback(event)

    def _phase_finished(self) -> None:
        self._done += 1
        if self._total:
            pct = int(min(self._done / self._total, 1.0) * 100)
            self._emit(ProgressEvent("overall", percent=pct))
