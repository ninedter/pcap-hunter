# tests/test_jobs_schema.py
"""Schema-level tests for the jobs table."""

from __future__ import annotations

from app.database.repository import CaseRepository


def test_jobs_table_exists(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "test.db"))
    conn = repo._get_conn()
    try:
        row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='jobs'").fetchone()
    finally:
        conn.close()
    assert row is not None, "jobs table should exist"


def test_cases_has_source_column(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "test.db"))
    conn = repo._get_conn()
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(cases)").fetchall()]
    finally:
        conn.close()
    assert "source" in cols, "cases.source column should exist for ui/api distinction"


def test_analyses_has_attack_json_column(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "test.db"))
    conn = repo._get_conn()
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(analyses)").fetchall()]
    finally:
        conn.close()
    assert "attack_json" in cols, "analyses.attack_json column should exist for persisted ATT&CK mappings"


def test_jobs_table_columns(tmp_path):
    """Verify the jobs table has all expected columns."""
    repo = CaseRepository(db_path=str(tmp_path / "test.db"))
    conn = repo._get_conn()
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(jobs)").fetchall()}
    finally:
        conn.close()
    expected = {
        "id",
        "case_id",
        "pcap_path",
        "options_json",
        "status",
        "progress_stage",
        "progress_done",
        "progress_total",
        "submitted_at",
        "started_at",
        "finished_at",
        "heartbeat_at",
        "error_code",
        "error_detail",
        "result_json",
    }
    assert expected.issubset(cols), f"Missing columns: {expected - cols}"
