"""Configuration persistence manager with encryption for sensitive values."""

from __future__ import annotations

import base64
import json
import logging
import os
import platform
import stat
import tempfile
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from filelock import FileLock

from app import config as C

logger = logging.getLogger(__name__)

# Keys that should be encrypted
SENSITIVE_KEYS = {
    "cfg_vt_key",
    "cfg_greynoise_key",
    "cfg_shodan_key",
    "cfg_abuseipdb_key",
    "cfg_otx_key",
    "cfg_openai_key",  # LM Studio API key (legacy name, encrypted at rest)
    "cfg_openai_cloud_key",  # OpenAI cloud provider key
    "cfg_anthropic_key",  # Anthropic provider key
}

# Default configuration values
DEFAULT_CONFIG = {
    "cfg_llm_endpoint": C.LM_BASE_URL,
    "cfg_llm_model": C.LM_MODEL,
    "cfg_llm_language": "US English",
    "cfg_llm_provider": "lmstudio",
    "cfg_llm_context_window": C.LLM_CONTEXT_WINDOW_DEFAULT,
    "cfg_llm_unlimited_context": False,
    "cfg_openai_model": "gpt-4o",
    "cfg_openai_base_url": "",
    "cfg_anthropic_model": "claude-opus-4-8",
    "cfg_pyshark_limit": 200000,
    "cfg_osint_top_ips": 50,
    "cfg_osint_cache_enabled": False,  # Enable/disable OSINT response caching
    "cfg_yara_rules_dir": "",  # User-configured YARA rules directory
    "cfg_vt_key": "",
    "cfg_greynoise_key": "",
    "cfg_shodan_key": "",
    "cfg_abuseipdb_key": "",
    "cfg_otx_key": "",
    "cfg_openai_key": "",
    "cfg_openai_cloud_key": "",
    "cfg_anthropic_key": "",
}


class ConfigManager:
    """Persist settings with a random, separately stored Fernet key.

    Legacy machine-derived ciphertext is read only for atomic migration. New
    ciphertext can be decrypted only with the protected key file (or injected
    PCAP_HUNTER_CONFIG_KEY). Back up that key together with the configuration.
    """

    _LEGACY_SALT = b"pcap_hunter_v1_salt"

    def __init__(self, config_path: str | Path | None = None):
        self.config_path = Path(config_path or Path.home() / ".pcap_hunter_config.json")
        self.config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.key_path = Path(os.getenv("PCAP_HUNTER_CONFIG_KEY_FILE") or str(self.config_path) + ".key")
        self._lock = FileLock(str(self.config_path) + ".lock", timeout=30, mode=0o600)
        self.defaults = DEFAULT_CONFIG.copy()
        with self._lock:
            self._fernet = Fernet(self._master_key())

    def _master_key(self) -> bytes:
        injected = os.getenv("PCAP_HUNTER_CONFIG_KEY")
        if injected:
            key = injected.encode("ascii")
            Fernet(key)  # Validate without logging its value.
            return key
        self.key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with FileLock(str(self.key_path) + ".lock", timeout=30, mode=0o600):
            return self._file_master_key()

    def _file_master_key(self) -> bytes:
        if not self.key_path.exists():
            raw = self._read_saved()
            if any(isinstance(v, str) and v.startswith("ENC2[") for v in raw.values()):
                raise ValueError("Saved configuration encryption key is missing; restore the key backup.")
            self.key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(self.key_path, flags, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as output:
                    output.write(Fernet.generate_key())
                    output.flush()
                    os.fsync(output.fileno())
        fd = os.open(self.key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or (os.name == "posix" and info.st_mode & 0o077):
                raise ValueError("Configuration encryption key must be a private regular file (mode 0600).")
            key = source.read(128).strip()
        Fernet(key)
        return key

    def _read_saved(self) -> dict[str, Any]:
        try:
            saved = json.loads(self.config_path.read_text(encoding="utf-8"))
            return saved if isinstance(saved, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _legacy_fernet(self, saved: dict) -> Fernet:
        salt = base64.b64decode(saved["_salt"], validate=True) if saved.get("_salt") else self._LEGACY_SALT
        identity = f"{os.getenv('USER', os.getenv('USERNAME', 'user'))}@{platform.node()}".encode()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return Fernet(base64.urlsafe_b64encode(kdf.derive(identity)))

    def _encrypt(self, value: str) -> str:
        return "ENC2[" + self._fernet.encrypt(value.encode()).decode() + "]" if value else ""

    def _decode(self, value: Any, saved: dict) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            raise ValueError("Saved credential has an invalid format.")
        try:
            if value.startswith("ENC2["):
                return self._fernet.decrypt(value[5:-1].encode()).decode()
            if value.startswith("ENC["):
                return self._legacy_fernet(saved).decrypt(value[4:-1].encode()).decode()
            return value
        except Exception as exc:
            raise ValueError(
                "Saved credentials cannot be decrypted; restore the configuration and key backup."
            ) from exc

    def load(self) -> dict[str, Any]:
        with self._lock:
            saved = self._read_saved()
            config = self.defaults.copy()
            migration = False
            for key, value in saved.items():
                if key.startswith("_"):
                    continue
                config[key] = self._decode(value, saved) if key in SENSITIVE_KEYS else value
                if key in SENSITIVE_KEYS and value and not value.startswith("ENC2["):
                    migration = True
            if migration:
                self._save_locked(config)
            return config

    def _save_locked(self, config: dict[str, Any]) -> None:
        saved = {"_encryption_version": 2}
        for key, value in config.items():
            if not key.startswith("_"):
                saved[key] = self._encrypt(str(value) if value else "") if key in SENSITIVE_KEYS else value
        fd, name = tempfile.mkstemp(prefix=".pcap-config-", dir=self.config_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump(saved, output, indent=2)
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, self.config_path)
        finally:
            Path(name).unlink(missing_ok=True)

    def save(self, config: dict[str, Any]) -> None:
        if not isinstance(config, dict):
            raise TypeError("Config must be a dictionary")
        with self._lock:
            self._save_locked(config)

    def get(self, key: str, default: Any = None) -> Any:
        return self.load().get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            config = self.load()
            config[key] = value
            self._save_locked(config)

    def clear(self) -> None:
        with self._lock:
            self.config_path.unlink(missing_ok=True)


# Global instance for convenience
_config_manager: ConfigManager | None = None


def get_config_manager(config_path: str | Path | None = None) -> ConfigManager:
    """Get or create the global config manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager
