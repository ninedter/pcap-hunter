from __future__ import annotations

import os
import signal
import subprocess
import time

from app.utils.common import find_bin
from app.utils.logger import log_runtime_error


class LiveCapture:
    """Manages a live tshark capture process."""

    def __init__(self, interface: str, output_path: str):
        self.interface = interface
        self.output_path = output_path
        self.process: subprocess.Popen | None = None
        self.start_time: float = 0

    @staticmethod
    def _validate_interface(interface: str) -> None:
        """Validate the interface name to prevent command injection.

        Args:
            interface: Network interface name

        Raises:
            ValueError: If the interface name is invalid
        """
        if not interface or interface.startswith("-"):
            raise ValueError(f"Invalid interface name: {interface!r}")

        # If we can enumerate interfaces, validate against the list
        available = list_interfaces()
        if available and interface not in available:
            raise ValueError(f"Interface {interface!r} not found. Available: {', '.join(available)}")

    def start(self):
        """Starts the tshark capture."""
        self._validate_interface(self.interface)

        tshark_path = find_bin("tshark", cfg_key="cfg_tshark_bin")
        if not tshark_path:
            raise RuntimeError("Tshark binary not found.")

        cmd = [
            tshark_path,
            "-i",
            self.interface,
            "-w",
            self.output_path,
            "-n",  # Disable name resolution to speed up capture
        ]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,  # Create a new process group to kill it safely
            )
            self.start_time = time.time()

            # Wait a moment to see if it crashes immediately (e.g. permissions)
            time.sleep(0.5)
            if self.process.poll() is not None:
                _, stderr = self.process.communicate()
                raise RuntimeError(f"Tshark exited immediately: {stderr.strip()}")

        except Exception as e:
            log_runtime_error(f"Failed to start tshark: {e}")
            raise

    def stop(self):
        """Stops the tshark capture."""
        if not self.process:
            return

        try:
            # Kill the process group
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            self.process.wait(timeout=5)
        except Exception as e:
            log_runtime_error(f"Error stopping tshark: {e}")
            if self.process:
                self.process.kill()
        finally:
            self.process = None

    def is_running(self) -> bool:
        """Checks if the capture is still running."""
        return self.process is not None and self.process.poll() is None


def list_interfaces() -> list[str]:
    """Lists available network interfaces using tshark -D."""
    tshark_path = find_bin("tshark", cfg_key="cfg_tshark_bin")
    if not tshark_path:
        return []

    try:
        result = subprocess.run([tshark_path, "-D"], capture_output=True, text=True, check=True)
        interfaces = []
        for line in result.stdout.splitlines():
            # Format: 1. en0 (Wi-Fi)
            parts = line.split(". ")
            if len(parts) > 1:
                iface_name = parts[1].split()[0]
                interfaces.append(iface_name)
        return interfaces
    except Exception as e:
        log_runtime_error(f"Failed to list interfaces: {e}")
        return []
