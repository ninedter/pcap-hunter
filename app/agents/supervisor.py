"""Trusted Docker launcher. Capture parsers never receive this service's socket or spool."""

from __future__ import annotations

import http.client
import json
import logging
import os
import re
import signal
import socket
import stat
import struct
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlencode

from app.agents.spool import atomic_json, input_root, output_root

JOB = re.compile(r"j_[a-f0-9]{16}")
OWNER = "org.pcap-hunter.runner"
MANAGED = "org.pcap-hunter.agent-job"
JOB_LABEL = "org.pcap-hunter.job"
MAX_RESULT = 32 * 1024 * 1024
logger = logging.getLogger(__name__)


class DockerError(RuntimeError):
    def __init__(self, status):
        super().__init__(f"Docker operation failed ({status})")
        self.status = status


class CleanupError(RuntimeError):
    """A parser may still be alive; never publish a terminal acknowledgement."""


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=5)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Docker:
    def __init__(self, path="/var/run/docker.sock"):
        self.path = path

    def request(self, method, path, payload=None, maximum=512 * 1024, missing=False):
        connection = UnixConnection(self.path)
        try:
            body = None if payload is None else json.dumps(payload).encode()
            connection.request(method, "/v1.47" + path, body, {"Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(maximum + 1)
            if response.status == 404 and missing:
                return None
            if not 200 <= response.status < 300:
                raise DockerError(response.status)
            if len(raw) > maximum:
                raise ValueError("Docker response exceeds its limit")
            return raw
        finally:
            connection.close()

    def json(self, method, path, payload=None, **kwargs):
        raw = self.request(method, path, payload, **kwargs)
        return None if raw is None else json.loads(raw or b"{}")

    def read_file(self, container, path, maximum):
        # -I -S ignores PYTHONPATH, user-site hooks and Python environment overrides.
        # The immutable system interpreter opens a regular file without following links.
        program = """import os,stat,sys
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as source:
  metadata=os.fstat(source.fileno()); limit=int(sys.argv[2])
  if not stat.S_ISREG(metadata.st_mode) or metadata.st_size>limit:sys.exit(4)
  raw=source.read(limit+1)
  if len(raw)>limit:sys.exit(4)
 sys.stdout.buffer.write(raw)
except FileNotFoundError:sys.exit(3)
except Exception:sys.exit(4)
"""
        created = self.json(
            "POST",
            f"/containers/{container}/exec",
            {
                "AttachStdout": True,
                "AttachStderr": False,
                "User": "1000:1000",
                "Cmd": ["/usr/bin/python3.13", "-I", "-S", "-c", program, path, str(maximum)],
            },
        )
        exec_id = created["Id"]
        if not re.fullmatch(r"[a-f0-9]{64}", exec_id):
            raise ValueError("Invalid reader identity")
        raw = self.request(
            "POST", f"/exec/{exec_id}/start", {"Detach": False, "Tty": False}, maximum=maximum + 64 * 1024
        )
        status = self.json("GET", f"/exec/{exec_id}/json")
        if status.get("Running"):
            raise ValueError("Job reader did not finish")
        if status["ExitCode"] == 3:
            return None
        if status["ExitCode"] != 0:
            raise ValueError("Invalid job result file")
        return decode_stdout(raw, maximum)


def decode_stdout(raw, maximum):
    """Bound and validate Docker's non-TTY stdout frames before returning opaque bytes."""
    output, offset = bytearray(), 0
    while offset < len(raw):
        if len(raw) - offset < 8 or raw[offset : offset + 4] != b"\x01\x00\x00\x00":
            raise ValueError("Invalid job reader frame")
        length = struct.unpack(">I", raw[offset + 4 : offset + 8])[0]
        if offset + 8 + length > len(raw) or len(output) + length > maximum:
            raise ValueError("Oversized or truncated job reader output")
        output.extend(raw[offset + 8 : offset + 8 + length])
        offset += 8 + length
    return bytes(output)


def read_regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("Invalid job input")
        raw = source.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("Invalid job input")
        return json.loads(raw)


def job_spec(job_id, image, volume, owner):
    if not JOB.fullmatch(job_id) or not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise ValueError("Invalid job identity")
    return {
        "Image": image,
        "User": "1000:1000",
        "WorkingDir": "/app",
        "Entrypoint": ["python", "-m", "app.agents.worker"],
        "Cmd": ["--job", job_id],
        "Env": [
            "HOME=/job/home",
            "TMPDIR=/job/tmp",
            "PCAP_HUNTER_DATA_DIR=/job/work",
            "PCAP_HUNTER_AGENT_INPUT=/job/inbox",
            "PCAP_HUNTER_AGENT_OUTPUT=/job/results",
        ],
        "Labels": {OWNER: owner, MANAGED: "1", JOB_LABEL: job_id},
        "Healthcheck": {"Test": ["NONE"]},
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidMode": "",
            "IpcMode": "private",
            "CgroupnsMode": "private",
            "Init": True,
            "Memory": 3 * 1024**3,
            "MemorySwap": 3 * 1024**3,
            "NanoCpus": 2_000_000_000,
            "PidsLimit": 256,
            "Ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 1024}],
            "LogConfig": {"Type": "none", "Config": {}},
            "Tmpfs": {
                "/job": "rw,nosuid,nodev,size=2g,uid=1000,gid=1000,mode=0700",
                "/tmp": "rw,nosuid,nodev,size=128m,mode=1777",
            },
            "Mounts": [
                {
                    "Type": "volume",
                    "Source": volume,
                    "Target": "/job/inbox/" + job_id,
                    "ReadOnly": True,
                    "VolumeOptions": {"NoCopy": True, "Subpath": job_id},
                }
            ],
        },
    }


class Supervisor:
    def __init__(self, docker, image, volume, owner, *, budget=600, stopping=None):
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", owner):
            raise ValueError("Invalid runner owner")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", volume):
            raise ValueError("Invalid input volume")
        self.docker, self.volume, self.owner = docker, volume, owner
        self.budget, self.stopping = budget, stopping or threading.Event()
        inspected = docker.json("GET", "/images/" + quote(image, safe="") + "/json")
        self.image, self.platform = inspected["Id"], "linux/" + inspected["Architecture"]
        if inspected["Os"] != "linux" or inspected["Architecture"] not in {"amd64", "arm64"}:
            raise ValueError("Unsupported job image platform")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", self.image):
            raise ValueError("Job image must resolve to an immutable image")
        metadata = docker.json("GET", "/volumes/" + quote(volume, safe=""))
        if metadata.get("Labels", {}).get("com.docker.compose.project") != owner:
            raise ValueError("Input volume belongs to a different Compose project")
        info = docker.json("GET", "/info")
        if not any(s.startswith("name=seccomp,") and "unconfined" not in s for s in info["SecurityOptions"]):
            raise ValueError("Docker's default seccomp policy is required")

    def owned(self, container):
        labels = container.get("Labels", {})
        job_id = labels.get(JOB_LABEL, "")
        expected = "/ph-" + self.owner + "-" + job_id
        return (
            labels.get(OWNER) == self.owner
            and labels.get(MANAGED) == "1"
            and JOB.fullmatch(job_id)
            and expected in container.get("Names", [])
        )

    def recover(self):
        query = urlencode({"all": "1", "filters": json.dumps({"label": [OWNER + "=" + self.owner, MANAGED + "=1"]})})
        for container in self.docker.json("GET", "/containers/json?" + query):
            if self.owned(container):
                self.docker.request("DELETE", "/containers/" + container["Id"] + "?force=1&v=0")

    def run_job(self, job_id):
        folder = input_root() / job_id
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError("Invalid job directory")
        request = read_regular(folder / "request.json", 4096)
        if not isinstance(request, dict):
            raise ValueError("Invalid job request")
        case_id = request.get("case_id")
        if (
            request.get("job_id") != job_id
            or not isinstance(case_id, str)
            or not re.fullmatch(r"[a-f0-9]{12}", case_id)
        ):
            raise ValueError("Invalid job request")
        if folder.is_symlink() or (folder / "capture.pcap").is_symlink():
            raise ValueError("Invalid job input")
        capture = (folder / "capture.pcap").stat()
        if not stat.S_ISREG(capture.st_mode) or not 24 <= capture.st_size <= 100 * 1024**2:
            raise ValueError("Invalid job capture")
        if (folder / "cancel.json").exists():
            return {"ok": False, "error_code": "cancelled"}
        name = "ph-" + self.owner + "-" + job_id
        query = urlencode({"name": name, "platform": self.platform})
        created = self.docker.json(
            "POST", "/containers/create?" + query, job_spec(job_id, self.image, self.volume, self.owner)
        )
        container = created["Id"]
        if not re.fullmatch(r"[a-f0-9]{64}", container):
            raise ValueError("Invalid container identity")
        try:
            self.docker.request("POST", f"/containers/{container}/start")
            deadline = time.monotonic() + self.budget
            while not self.stopping.is_set():
                if (folder / "cancel.json").exists():
                    return {"ok": False, "error_code": "cancelled"}
                if time.monotonic() >= deadline:
                    return {"ok": False, "error_code": "agent_time_budget_exceeded"}
                inspected = self.docker.json("GET", f"/containers/{container}/json")
                if not inspected["State"]["Running"]:
                    return {"ok": False, "error_code": "offline_worker_failed"}
                Path("/tmp/agent-worker-heartbeat").touch()
                atomic_json(output_root() / (job_id + ".heartbeat"), {"heartbeat": time.time()})
                try:
                    result = self.docker.read_file(container, "/job/results/" + job_id + ".json", MAX_RESULT)
                except DockerError as error:
                    raise ValueError("Unreadable parser output") from error
                if result is not None:
                    receipt = {
                        "job_id": job_id,
                        "backend": "docker-per-job",
                        "image_id": self.image,
                        "container_id": container,
                        "network": "none",
                        "input_scope": "single-read-only-job",
                        "scratch": "private-tmpfs",
                    }
                    return result, receipt
                self.stopping.wait(1)
            return None  # A restart replays this job; never acknowledge a live parser.
        finally:
            # Publishing a terminal result happens only after all job processes are gone.
            try:
                self.docker.request("DELETE", f"/containers/{container}?force=1&v=0")
            except (DockerError, OSError) as error:
                raise CleanupError("Unable to confirm parser removal") from error

    def serve(self):
        output_root().mkdir(parents=True, exist_ok=True)
        self.recover()
        while not self.stopping.is_set():
            self.docker.request("GET", "/_ping")
            Path("/tmp/agent-worker-heartbeat").touch()
            for folder in sorted(input_root().glob("j_*")):
                if self.stopping.is_set():
                    break
                job_id = folder.name
                if not JOB.fullmatch(job_id) or folder.is_symlink():
                    continue
                output = output_root() / (job_id + ".json")
                if output.exists() or not (folder / "request.json").exists():
                    continue
                try:
                    payload = self.run_job(job_id)
                except (ValueError, OSError, RecursionError):
                    payload = {"ok": False, "error_code": "offline_worker_failed"}
                    logger.exception("Invalid isolated job %s", job_id)
                if isinstance(payload, tuple):
                    data, receipt = payload
                    atomic_json(output_root() / (job_id + ".isolation"), receipt)
                    temporary = output.with_suffix(".collecting")
                    try:
                        temporary.write_bytes(data)
                        os.replace(temporary, output)
                    finally:
                        temporary.unlink(missing_ok=True)
                elif payload is not None:
                    atomic_json(output, payload)
            for cached in output_root().iterdir():
                job_id = cached.name.split(".", 1)[0]
                if JOB.fullmatch(job_id) and not (input_root() / job_id).exists():
                    if time.time() - cached.lstat().st_mtime > 60:
                        cached.unlink(missing_ok=True)
            self.stopping.wait(1)


def main():
    logging.basicConfig(level=logging.INFO)
    stopping = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stopping.set())
    supervisor = Supervisor(
        Docker(os.getenv("PCAP_HUNTER_DOCKER_SOCKET", "/var/run/docker.sock")),
        os.environ["PCAP_HUNTER_JOB_IMAGE"],
        os.environ["PCAP_HUNTER_AGENT_INPUT_VOLUME"],
        os.environ["PCAP_HUNTER_RUNNER_OWNER"],
        stopping=stopping,
    )
    supervisor.serve()


if __name__ == "__main__":
    main()
