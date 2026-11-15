"""The analysis engine must import (and log errors) with Streamlit unavailable.

API and agent workers run the pipeline headlessly. ``sys.modules["streamlit"] = None``
makes any ``import streamlit`` raise ImportError, which is exactly what a container
without the UI dependency would do.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

_BLOCK = "import sys; sys.modules['streamlit'] = None\n"


def _run(code: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    return subprocess.run(
        [sys.executable, "-c", _BLOCK + code],
        env=env,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_every_pipeline_module_imports_without_streamlit():
    code = """
import importlib, pkgutil
import app.pipeline as pkg
failed = []
for mod in pkgutil.iter_modules(pkg.__path__):
    name = "app.pipeline." + mod.name
    try:
        importlib.import_module(name)
    except Exception as exc:
        failed.append(f"{name}: {type(exc).__name__}: {exc}")
from app.pipeline.state import PhaseHandle, PhaseTracker, StreamlitProgressAdapter  # legacy import path
from app.pipeline.progress import PhaseHandle as ProtocolHandle
from app.pipeline.runner import PipelineOptions, run_pipeline
import app.analysis.visibility, app.utils.common, app.utils.network_utils
assert sys.modules.get("streamlit") is None, "something imported streamlit"
print("\\n".join(failed))
sys.exit(1 if failed else 0)
"""
    result = _run(code)
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"


def test_error_paths_work_without_streamlit(tmp_path):
    """log_runtime_error / find_bin / the parser's early returns must not need Streamlit."""
    missing = tmp_path / "missing.pcap"
    code = f"""
from app.utils.logger import log_runtime_error
from app.utils.binary_discovery import find_bin
from app.pipeline.pyshark_pass import parse_pcap_pyshark
log_runtime_error("headless failure message")
assert find_bin("no-such-binary-xyz", cfg_key="cfg_tshark_bin") is None
out = parse_pcap_pyshark({str(missing)!r}, limit_packets=None, phase=None, total_packets=None)
assert out["flows"] == [] and out["artifacts"]["macs"] == [], out
assert out["parse_stats"]["error"] == "pcap_not_found", out
"""
    result = _run(code)
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
    assert "headless failure message" in result.stderr  # still reaches the log


def test_streamlit_only_helpers_fail_loudly_not_at_import():
    """Using a UI-only helper without Streamlit raises ImportError at call time."""
    code = """
from app.pipeline import state
try:
    state.is_run_active()
except ImportError:
    sys.exit(0)
sys.exit(1)
"""
    result = _run(code)
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
