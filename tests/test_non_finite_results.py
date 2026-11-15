"""Non-finite floats must never reach strict-JSON sinks.

``rank_beaconing`` returns a DataFrame, and pandas represents an absent metric
(for example ``jitter_pct`` on a row that has no interval statistics) as NaN.
The agent result spool serialises with ``allow_nan=False``, so one such row
used to fail every agent capture submission with ``offline_worker_failed``.
"""

from __future__ import annotations

import json
import math
import shutil
from pathlib import Path

import pytest

from app.agents.registry import canonical
from app.agents.worker import _finite
from app.pipeline.progress import CallbackProgress
from app.pipeline.runner import PipelineOptions, run_pipeline

FIXTURE = Path(__file__).parent / "fixtures" / "e2e_small.pcap"


class TestFiniteHelper:
    def test_replaces_nan_and_infinity_recursively(self):
        payload = {"a": float("nan"), "b": [1.5, float("inf"), {"c": float("-inf"), "d": "nan"}], "e": (2.0,)}
        assert _finite(payload) == {"a": None, "b": [1.5, None, {"c": None, "d": "nan"}], "e": [2.0]}

    def test_result_is_accepted_by_the_strict_spool_encoder(self):
        assert json.loads(canonical(_finite({"jitter_pct": float("nan")}))) == {"jitter_pct": None}


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark is required to parse the fixture")
class TestPipelineResultIsStrictJson:
    def test_beacon_records_contain_no_non_finite_floats(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        options = PipelineOptions(osint_enabled=False, llm_enabled=False, pyshark_packet_limit=200000)
        result = run_pipeline(str(FIXTURE), "0123456789ab", options, CallbackProgress(lambda event: None))

        assert result.beacon_df_records, "the fixture contains a periodic flow and must produce beacon rows"
        offenders = [
            (index, key)
            for index, record in enumerate(result.beacon_df_records)
            for key, value in record.items()
            if isinstance(value, float) and not math.isfinite(value)
        ]
        assert offenders == []
        # The exact encoder the agent worker uses must accept the whole result.
        canonical(result.to_dict() | {"features": result.features})
