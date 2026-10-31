"""Per-job lifecycle and hostile output boundaries, without a Docker socket in unit tests."""

import json
import struct
import threading

import pytest

from app.agents.spool import bounded_json
from app.agents.supervisor import (
    JOB_LABEL,
    MANAGED,
    OWNER,
    CleanupError,
    Supervisor,
    decode_stdout,
    job_spec,
)

JOB_ID = "j_0123456789abcdef"
IMAGE = "sha256:" + "a" * 64
CONTAINER = "b" * 64


class Engine:
    def __init__(self):
        self.events, self.containers = [], []
        self.result = b'{"ok":true}'
        self.delete_error = False
        self.after_start = lambda: None
        self.after_delete = lambda: None

    def json(self, method, path, payload=None):
        if path.startswith("/images/"):
            return {"Id": IMAGE, "Architecture": "arm64", "Os": "linux"}
        if path.startswith("/volumes/"):
            return {"Labels": {"com.docker.compose.project": "test"}}
        if path == "/info":
            return {"SecurityOptions": ["name=seccomp,profile=builtin"]}
        if path.startswith("/containers/create"):
            self.events.append(("create", payload))
            return {"Id": CONTAINER}
        if path.startswith("/containers/json"):
            return self.containers
        return {"State": {"Running": True}}

    def request(self, method, path):
        self.events.append((method, path))
        if path.endswith("/start"):
            self.after_start()
        if method == "DELETE":
            if self.delete_error:
                raise OSError("unavailable")
            self.after_delete()
        return b"OK"

    def read_file(self, *args):
        return self.result


@pytest.fixture
def runner(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAP_HUNTER_AGENT_SPOOL", str(tmp_path))
    monkeypatch.delenv("PCAP_HUNTER_AGENT_INPUT", raising=False)
    monkeypatch.delenv("PCAP_HUNTER_AGENT_OUTPUT", raising=False)
    folder = tmp_path / "inbox" / JOB_ID
    folder.mkdir(parents=True)
    (folder / "request.json").write_text(json.dumps({"job_id": JOB_ID, "case_id": "0123456789ab"}))
    (folder / "capture.pcap").write_bytes(b"P" * 24)
    (tmp_path / "results").mkdir()
    engine = Engine()
    return Supervisor(engine, "trusted-image", "input", "test"), engine, tmp_path


def test_job_security_contract_and_no_inherited_secrets():
    spec = job_spec(JOB_ID, IMAGE, "input", "test")
    host = spec["HostConfig"]
    assert spec["User"] == "1000:1000" and host["NetworkMode"] == "none"
    assert host["ReadonlyRootfs"] and not host["Privileged"]
    assert host["CapDrop"] == ["ALL"] and host["SecurityOpt"] == ["no-new-privileges:true"]
    assert host["PidMode"] == "" and host["IpcMode"] == host["CgroupnsMode"] == "private"
    assert host["Mounts"] == [
        {
            "Type": "volume",
            "Source": "input",
            "Target": "/job/inbox/" + JOB_ID,
            "ReadOnly": True,
            "VolumeOptions": {"NoCopy": True, "Subpath": JOB_ID},
        }
    ]
    assert host["Memory"] == host["MemorySwap"] == 3 * 1024**3 and host["PidsLimit"] == 256
    assert host["LogConfig"]["Type"] == "none"
    assert set(host["Tmpfs"]) == {"/job", "/tmp"}
    assert all("KEY" not in value and "TOKEN" not in value for value in spec["Env"])
    for value in ("../job", "j_" + "x" * 16):
        with pytest.raises(ValueError):
            job_spec(value, IMAGE, "input", "test")


def test_bounded_stdout_rejects_truncation_extra_streams_and_oversized_frames():
    def frame(value):
        return b"\x01\x00\x00\x00" + struct.pack(">I", len(value)) + value

    assert decode_stdout(frame(b'{"ok":true}'), 100) == b'{"ok":true}'
    for raw in (b"short", frame(b"x")[:-1], b"\x02" + frame(b"x")[1:], frame(b"x" * 101)):
        with pytest.raises(ValueError):
            decode_stdout(raw, 100)
    with pytest.raises(ValueError):
        decode_stdout(frame(b"x" * 60) + frame(b"y" * 60), 100)


def test_parser_json_is_validated_only_in_broker():
    for data in (b"[" * 65 + b"0" + b"]" * 65, b'{"n":NaN}', b'{"n":Infinity}', b'{"n":"\\ud800"}'):
        with pytest.raises(ValueError):
            bounded_json(data)
    with pytest.raises(ValueError, match="complexity"):
        bounded_json(b"[" + b"0," * 1_000_001 + b"0]")
    assert bounded_json(b'{"text":"[,{escaped]", "rows":[1,2]}')["rows"] == [1, 2]


def test_container_removed_before_any_result_is_published(runner):
    supervisor, engine, root = runner
    engine.after_delete = lambda: supervisor.stopping.set()
    supervisor.serve()
    assert (root / "results" / (JOB_ID + ".json")).read_bytes() == engine.result
    receipt = json.loads((root / "results" / (JOB_ID + ".isolation")).read_text())
    assert receipt["image_id"] == IMAGE and receipt["container_id"] == CONTAINER
    assert receipt["job_id"] == JOB_ID and receipt["input_scope"] == "single-read-only-job"
    assert engine.events[-1] == ("DELETE", f"/containers/{CONTAINER}?force=1&v=0")


def test_cleanup_failure_never_acknowledges_a_still_live_parser(runner):
    supervisor, engine, root = runner
    engine.delete_error = True
    with pytest.raises(CleanupError):
        supervisor.serve()
    assert not (root / "results" / (JOB_ID + ".json")).exists()
    assert not (root / "results" / (JOB_ID + ".isolation")).exists()


def test_cancellation_stops_the_entire_job_container(runner):
    supervisor, engine, root = runner
    engine.after_start = lambda: (root / "inbox" / JOB_ID / "cancel.json").write_text("{}")
    result = supervisor.run_job(JOB_ID)
    assert result["error_code"] == "cancelled"
    assert engine.events[-1] == ("DELETE", f"/containers/{CONTAINER}?force=1&v=0")


def test_budget_stops_job_and_interruption_is_retryable(runner):
    supervisor, engine, _ = runner
    supervisor.budget = 0
    assert supervisor.run_job(JOB_ID)["error_code"] == "agent_time_budget_exceeded"
    assert engine.events[-1][0] == "DELETE"
    supervisor.stopping = threading.Event()
    supervisor.stopping.set()
    assert supervisor.run_job(JOB_ID) is None
    assert engine.events[-1][0] == "DELETE"


def test_recovery_never_deletes_other_containers_or_volumes(runner):
    supervisor, engine, _ = runner
    labels = {OWNER: "test", MANAGED: "1", JOB_LABEL: JOB_ID}
    engine.containers = [
        {"Id": CONTAINER, "Labels": labels, "Names": ["/ph-test-" + JOB_ID]},
        {"Id": "c" * 64, "Labels": labels | {OWNER: "other"}, "Names": ["/ph-other-" + JOB_ID]},
        {"Id": "d" * 64, "Labels": labels, "Names": ["/unrelated"]},
    ]
    supervisor.recover()
    assert engine.events == [("DELETE", f"/containers/{CONTAINER}?force=1&v=0")]


def test_invalid_input_cannot_choose_mounts_or_follow_links(runner):
    supervisor, engine, root = runner
    request = root / "inbox" / JOB_ID / "request.json"
    request.unlink()
    request.symlink_to(root / "protected")
    (root / "protected").write_text('{"secret":"inert"}')
    with pytest.raises(OSError):
        supervisor.run_job(JOB_ID)
    assert engine.events == []


def test_image_volume_and_seccomp_requirements_fail_closed(monkeypatch):
    for changed in ("volume", "image", "seccomp"):
        engine = Engine()
        original = engine.json

        def altered(method, path, payload=None):
            result = original(method, path, payload)
            if changed == "volume" and path.startswith("/volumes/"):
                return {"Labels": {"com.docker.compose.project": "other"}}
            if changed == "image" and path.startswith("/images/"):
                return result | {"Id": "mutable-image"}
            if changed == "seccomp" and path == "/info":
                return {"SecurityOptions": []}
            return result

        monkeypatch.setattr(engine, "json", altered)
        with pytest.raises(ValueError):
            Supervisor(engine, "image", "input", "test")


def test_old_shared_worker_entrypoint_fails_closed(monkeypatch):
    from app.agents import worker

    monkeypatch.setattr("sys.argv", ["worker", "--job", JOB_ID])
    monkeypatch.setenv("PCAP_HUNTER_AGENT_INPUT", "/agent-inbox")
    with pytest.raises(ValueError, match="private job container"):
        worker.main()
