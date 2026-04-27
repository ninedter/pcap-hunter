# app/pipeline/runner.py
"""Headless end-to-end pipeline runner.

The single shared entrypoint for running the 10-stage pipeline against a PCAP.
Both the Streamlit UI and the API worker call ``run_pipeline()``.

This file intentionally contains no Streamlit imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.pipeline.progress import Progress


@dataclass
class PipelineOptions:
    """Tunable knobs for a pipeline run."""

    osint_enabled: bool = True
    llm_enabled: bool = True
    do_pyshark: bool = True
    do_zeek: bool = True
    do_carve: bool = True
    do_yara: bool = True
    pre_count: bool = True
    pyshark_packet_limit: int | None = None
    osint_top_n: int = 50


@dataclass
class PipelineResult:
    """Structured output of a pipeline run."""

    case_id: str = ""
    analysis_id: str = ""
    packet_count: int = 0
    duration_seconds: float = 0.0
    stages_run: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary_narrative: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "analysis_id": self.analysis_id,
            "packet_count": self.packet_count,
            "duration_seconds": self.duration_seconds,
            "stages_run": list(self.stages_run),
            "warnings": list(self.warnings),
            "summary_narrative": self.summary_narrative,
            "mitre_techniques": list(self.mitre_techniques),
        }


def run_pipeline(
    pcap_path: str,
    case_id: str,
    options: PipelineOptions,
    progress: Progress,
    heartbeat: "callable | None" = None,
) -> PipelineResult:
    """Run the 10-stage pipeline against ``pcap_path`` and return a structured result.

    This is a stub; full orchestration lands in Task 4.
    """
    raise NotImplementedError("run_pipeline implementation lands in Task 4")
