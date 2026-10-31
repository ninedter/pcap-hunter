"""Fail the release build if a remediated native component regresses."""

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

MINIMUMS = {
    "libxml2": "2.15.4",
    "libxml2-16": "2.15.4",
    "libpcap": "1.10.7",
    "c-ares": "1.34.9",
    "cups-libs": "2.4.20",
    "libx11": "1.8.14",
    "libxrender": "0.9.13",
    "libxtst": "1.2.6",
    "ncurses": "6.6",
    "libmount": "2.42.4",
    "libblkid": "2.42.4",
    "libuuid": "2.42.4",
    "libsmartcols": "2.42.4",
    "libfdisk": "2.42.4",
    "util-linux": "2.42.4",
    "libsystemd": "261.2",
    "systemd": "261.2",
    "acl": "2.4.0",
    "libacl": "2.4.0",
    "tiff": "4.7.2",
}
REQUIRED = {"libxml2", "libpcap", "c-ares", "cups-libs", "libx11", "libxrender", "libmount"}
FORBIDDEN = ("libxml2-2.13", "libsndfile", "xdg-utils", "perl")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def version_output(executable):
    result = subprocess.run(
        [executable, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15
    )
    if result.returncode:
        linkage = subprocess.run(
            [executable],
            env=dict(os.environ, LD_TRACE_LOADED_OBJECTS="1"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
        ).stdout
        raise RuntimeError(f"{executable} cannot run: {result.stdout[-2000:]}\n{linkage[-6000:]}")
    return result.stdout


def xml_contract():
    from lxml import etree

    require(etree.LIBXML_VERSION >= (2, 15, 4), f"Affected XML library still linked: {etree.LIBXML_VERSION}")
    require(etree.LIBXML_COMPILED_VERSION >= (2, 15, 4), "XML binding used old headers")
    require(etree.fromstring(b"<capture><packet id='1'/></capture>")[0].get("id") == "1", "XML control failed")
    return {
        "binding": ".".join(map(str, etree.LXML_VERSION[:3])),
        "linked_libxml2": ".".join(map(str, etree.LIBXML_VERSION)),
    }


def verify():
    require("ID=wolfi" in Path("/etc/os-release").read_text().splitlines(), "Unexpected runtime distribution")
    packages = {}
    for block in Path("/lib/apk/db/installed").read_text().split("\n\n"):
        fields = dict(line.split(":", 1) for line in block.splitlines() if ":" in line)
        if "P" in fields:
            packages[fields["P"]] = fields["V"]
    require(REQUIRED <= packages.keys(), "A required runtime library is missing")
    for name, minimum in MINIMUMS.items():
        if name in packages:
            comparison = subprocess.check_output(["apk", "version", "-t", packages[name], minimum], text=True).strip()
            require(comparison in {"=", ">"}, f"Unpatched {name}: {packages[name]} < {minimum}")
    for prefix in FORBIDDEN:
        require(
            not any(name == prefix or name.startswith(prefix + "-") for name in packages), f"Unexpected {prefix} code"
        )
    require(shutil.which("xdg-mail") is None, "Unexpected mail client helper")
    from PIL import features

    tiff = features.version("libtiff")
    require(tuple(map(int, tiff.split("."))) >= (4, 7, 2), f"Old bundled TIFF library: {tiff}")
    tools = {}
    for name, minimum in {"tshark": (4, 6, 9), "zeek": (9, 0, 1)}.items():
        executable = shutil.which(name)
        text = version_output(executable)
        version = tuple(map(int, re.search(r"\b(\d+)\.(\d+)\.(\d+)", text).groups()))
        require(version >= minimum, f"Old {name}: {version}")
        tools[name] = ".".join(map(str, version))
    browser = os.environ["BROWSER_PATH"]
    text = version_output(browser)
    require("156.0.8078.73" in text, "Browser differs from the reviewed, pinned stable bundle")
    linked = subprocess.check_output(
        [shutil.which("tshark")], env=dict(os.environ, LD_TRACE_LOADED_OBJECTS="1"), text=True
    )
    require(
        bool(re.search(r"libxml2\.so\.16\s+=>\s+/usr/lib/libxml2\.so\.16", linked))
        and not re.search(r"libxml2\.so\.2(?:\s|$)", linked),
        "TShark must link the patched system XML library",
    )
    zeek_linked = subprocess.check_output(
        [shutil.which("zeek")], env=dict(os.environ, LD_TRACE_LOADED_OBJECTS="1"), text=True
    )
    require(
        bool(re.search(r"libcares\.so\.2\s+=>\s+/usr/lib/libcares\.so\.2", zeek_linked)),
        "Zeek must use patched system c-ares instead of its older bundled copy",
    )
    return {
        "schema_version": 1,
        "xml": xml_contract(),
        "tools": tools,
        "browser": text.strip(),
        "pillow_libtiff": tiff,
        "packages": {name: packages[name] for name in MINIMUMS if name in packages},
        "removed_component_families": list(FORBIDDEN),
        "tshark_xml_abi": "libxml2.so.16",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--xml-only", action="store_true")
    args = parser.parse_args()
    print(json.dumps(xml_contract() if args.xml_only else verify(), indent=2))
