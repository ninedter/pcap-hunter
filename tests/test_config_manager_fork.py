"""ConfigManager must stay usable in a forked worker.

The job queue forks its workers from a parent that has normally loaded the
saved configuration already. filelock raises if a lock object created in the
parent is acquired in the child, which made every worker lose its saved
settings and fail to persist the analysis.
"""

from __future__ import annotations

import multiprocessing
import sys

import pytest

from app.utils import config_manager as cm


def _load_in_child(conn) -> None:
    try:
        conn.send(("ok", cm.get_config_manager().load().get("cfg_osint_top_n")))
    except BaseException as exc:  # noqa: BLE001 - the parent asserts on the reported failure
        conn.send(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        conn.close()


@pytest.mark.skipif(sys.platform == "win32", reason="fork start method is POSIX-only")
class TestConfigManagerAcrossFork:
    def test_forked_child_can_load_config_created_by_parent(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cm, "_config_manager", None)
        manager = cm.get_config_manager(tmp_path / "config.json")
        manager.save({"cfg_osint_top_n": 17})
        assert manager.load()["cfg_osint_top_n"] == 17  # the parent has used its lock

        ctx = multiprocessing.get_context("fork")
        parent_conn, child_conn = ctx.Pipe(duplex=False)
        proc = ctx.Process(target=_load_in_child, args=(child_conn,))
        proc.start()
        child_conn.close()
        assert parent_conn.poll(30), "forked child did not report"
        status, value = parent_conn.recv()
        proc.join(30)

        assert (status, value) == ("ok", 17)
        # ...and the parent keeps working with its own lock afterwards.
        assert manager.load()["cfg_osint_top_n"] == 17
