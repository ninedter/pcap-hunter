"""Install one reviewed Google browser bundle during the image build."""

import argparse
import hashlib
import shutil
import stat
import tempfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "156.0.8078.73"
BUNDLES = {
    "arm64": ("linux-arm64", "98c084708f0f1fa4ed589ad601cc79b437f0cebe60ffc9794af78a085c01a2a7"),
    "amd64": ("linux64", "77eb8d52798efc7a857ab61abcc62a456d8ea9635b02341d06dffee2761768c8"),
}


def install(architecture, destination):
    platform, expected = BUNDLES[architecture]
    name = "chrome-headless-shell-" + platform
    url = f"https://storage.googleapis.com/chrome-for-testing-public/{VERSION}/{platform}/{name}.zip"
    with tempfile.TemporaryDirectory() as temporary:
        archive = Path(temporary) / "browser.zip"
        digest, size = hashlib.sha256(), 0
        with urllib.request.urlopen(url, timeout=120) as source, archive.open("wb") as output:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > 256 * 1024 * 1024:
                    raise ValueError("Browser bundle exceeds its build limit")
                digest.update(chunk)
                output.write(chunk)
        if digest.hexdigest() != expected:
            raise ValueError("Browser bundle checksum does not match the reviewed release")
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                path = Path(member.filename)
                if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != name:
                    raise ValueError("Invalid browser bundle path")
                if stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError("Browser bundle links are not allowed")
            bundle.extractall(temporary)
            for member in bundle.infolist():
                if not member.is_dir():
                    (Path(temporary) / member.filename).chmod((member.external_attr >> 16) & 0o755 or 0o644)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(Path(temporary) / name), str(destination))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("architecture", choices=BUNDLES)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    install(args.architecture, args.destination)
