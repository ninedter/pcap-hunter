"""Disposable real-engine attack controls for the production job security profile.

Run in a trusted test container with Docker access; job containers never receive it.
"""

import json
import os
import secrets
import struct
from urllib.parse import quote, urlencode

from app.agents.supervisor import Docker, job_spec


def execute(engine, container, code):
    created = engine.json(
        "POST",
        f"/containers/{container}/exec",
        {
            "AttachStdout": True,
            "AttachStderr": True,
            "Cmd": ["python", "-c", code],
        },
    )
    raw = engine.request("POST", "/exec/" + created["Id"] + "/start", {"Detach": False, "Tty": False}, maximum=65536)
    output, offset = bytearray(), 0
    while offset < len(raw):
        length = struct.unpack(">I", raw[offset + 4 : offset + 8])[0]
        output.extend(raw[offset + 8 : offset + 8 + length])
        offset += 8 + length
    status = engine.json("GET", "/exec/" + created["Id"] + "/json")
    if status["ExitCode"] != 0:
        raise RuntimeError(output.decode(errors="replace")[-2000:])
    return output.decode()


def probe():
    engine = Docker()
    image = engine.json("GET", "/images/" + quote(os.environ["PCAP_HUNTER_TEST_IMAGE"], safe="") + "/json")
    owner = "isolation-" + secrets.token_hex(6)
    volume = owner + "-input"
    jobs = ["j_" + secrets.token_hex(8), "j_" + secrets.token_hex(8)]
    containers = []
    created_volume = False
    try:
        engine.json("POST", "/volumes/create", {"Name": volume, "Labels": {"com.docker.compose.project": owner}})
        created_volume = True
        setup = "from pathlib import Path; import json\n"
        for job in jobs:
            setup += f"p=Path('/seed/{job}'); p.mkdir(); (p/'capture.pcap').write_bytes(b'P'*24); "
            setup += "(p/'capture.pcap').chmod(0o666); "
            setup += f"(p/'request.json').write_text(json.dumps({{'job_id':{job!r},'case_id':'0123456789ab'}}))\n"
        seed = engine.json(
            "POST",
            "/containers/create",
            {
                "Image": image["Id"],
                "User": "0:0",
                "Entrypoint": ["python", "-c", setup],
                "HostConfig": {
                    "NetworkMode": "none",
                    "ReadonlyRootfs": True,
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges:true"],
                    "Mounts": [{"Type": "volume", "Source": volume, "Target": "/seed"}],
                },
            },
        )["Id"]
        containers.append(seed)
        engine.request("POST", f"/containers/{seed}/start")
        assert engine.json("POST", f"/containers/{seed}/wait?condition=not-running")["StatusCode"] == 0
        engine.request("DELETE", f"/containers/{seed}?force=1&v=0")
        containers.remove(seed)

        def start(job):
            spec = job_spec(job, image["Id"], volume, owner)
            # Controlled probe command; all production isolation settings remain identical.
            spec["Entrypoint"], spec["Cmd"] = ["python", "-c"], ["import time; time.sleep(180)"]
            query = urlencode({"name": "ph-" + owner + "-" + job, "platform": "linux/" + image["Architecture"]})
            container = engine.json("POST", "/containers/create?" + query, spec)["Id"]
            containers.append(container)
            engine.request("POST", f"/containers/{container}/start")
            inspected = engine.json("GET", f"/containers/{container}/json")
            assert inspected["HostConfig"]["ReadonlyRootfs"]
            assert inspected["HostConfig"]["Memory"] == 3 * 1024**3
            assert inspected["HostConfig"]["PidsLimit"] == 256
            assert inspected["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"] == job
            assert len(inspected["Mounts"]) == 1 and not inspected["Mounts"][0]["RW"]
            return container

        first, second = start(jobs[0]), start(jobs[1])
        execute(engine, first, "from pathlib import Path; Path('/job/previous-job-marker').write_text('private')")
        checks = []
        for index, container in enumerate((first, second)):
            code = """import ctypes,errno,json,os,socket
from pathlib import Path
job=JOB_VALUE
other=OTHER_VALUE
assert Path('/job/inbox/'+job+'/capture.pcap').read_bytes()==b'P'*24
assert sorted(p.name for p in Path('/job/inbox').iterdir())==[job]
assert not Path('/job/inbox/'+other).exists()
for directory in ('/agent-inbox','/agent-results'):
 assert not any(Path(directory).iterdir())
for path in ('/var/run/docker.sock','/app/data/cases.db','/home/runner/.pcap_hunter_config.json'):
 assert not Path(path).exists(),path
for path in ('/job/inbox/'+job+'/capture.pcap','/app/untrusted-marker','/agent-results/forged.json'):
 try:Path(path).write_text('forged')
 except OSError as error:assert error.errno in (errno.EROFS,errno.EACCES,errno.ENOENT)
 else:raise AssertionError('Write escaped: '+path)
for address in (('1.1.1.1',443),('127.0.0.1',8000)):
 try:
  connection=socket.create_connection(address,timeout=0.3);connection.close()
 except OSError:pass
 else:raise AssertionError('Network escaped')
assert os.getuid()==1000
keys=('PCAP_HUNTER_AGENT_KEY','PCAP_HUNTER_API_KEY','OPENAI_API_KEY','ANTHROPIC_API_KEY')
assert all(not os.getenv(name) for name in keys)
status=Path('/proc/self/status').read_text()
assert 'CapEff:\\t0000000000000000' in status
assert 'NoNewPrivs:\\t1' in status and 'Seccomp:\\t2' in status
libc=ctypes.CDLL(None,use_errno=True)
assert libc.unshare(0x10000000)==-1 and ctypes.get_errno() in (errno.EPERM,errno.EACCES)
print(json.dumps({
 'namespaces':{n:os.readlink('/proc/self/ns/'+n) for n in ('pid','mnt','net','ipc')},
 'own_input_only':True,'read_only_input':True,'no_socket_database_or_secrets':True,
 'network_denied':True,'rootfs_write_denied':True,'privileges_denied':True,
 'previous_marker_exists':Path('/job/previous-job-marker').exists()}))
""".replace("JOB_VALUE", repr(jobs[index])).replace("OTHER_VALUE", repr(jobs[1 - index]))
            checks.append(json.loads(execute(engine, container, code)))
        result_path = "/job/reader-probe.json"
        execute(engine, first, "from pathlib import Path; Path('/job/reader-probe.json').write_bytes(b'{}')")
        assert engine.read_file(first, result_path, 100) == b"{}"
        assert engine.read_file(first, "/job/missing.json", 100) is None
        for statement in (
            "p.symlink_to('/job/inbox/" + jobs[0] + "/capture.pcap')",
            "os.mkfifo(p)",
            "p.write_bytes(b'x'*101)",
        ):
            execute(
                engine,
                first,
                "from pathlib import Path; import os; p=Path('/job/reader-probe.json'); p.unlink(); " + statement,
            )
            try:
                engine.read_file(first, result_path, 100)
            except ValueError:
                pass
            else:
                raise AssertionError("Unsafe result file was accepted")
        assert checks[0]["previous_marker_exists"] and not checks[1]["previous_marker_exists"]
        assert all(checks[0]["namespaces"][n] != checks[1]["namespaces"][n] for n in ("pid", "mnt", "net", "ipc"))
        engine.request("DELETE", f"/containers/{first}?force=1&v=0")
        containers.remove(first)
        replacement = start(jobs[0])
        assert replacement != first
        assert (
            execute(
                engine,
                replacement,
                "from pathlib import Path; assert not Path('/job/previous-job-marker').exists(); print('clean')",
            ).strip()
            == "clean"
        )
        return {
            "architecture": image["Architecture"],
            "image_id": image["Id"],
            "production_profile_controls": checks,
            "scratch_not_reused": True,
            "containers_removed": True,
        }
    finally:
        for container in containers:
            engine.request("DELETE", f"/containers/{container}?force=1&v=0", missing=True)
        if created_volume:
            engine.request("DELETE", "/volumes/" + volume)


if __name__ == "__main__":
    print(json.dumps(probe(), indent=2))
