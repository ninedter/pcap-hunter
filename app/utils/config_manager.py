"""Configuration persistence manager with encryption for sensitive values."""

from __future__ import annotations

import base64
import json
import logging
import os
import platform
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
    "cfg_llm_endpoint": "http://localhost:11434/v1",
    "cfg_llm_model": "llama3.1:8b",
    "cfg_llm_language": "US English",
    "cfg_llm_provider": "lmstudio",
    "cfg_openai_model": "gpt-4o",
    "cfg_openai_base_url": "",
    "cfg_anthropic_model": "claude-opus-4-8",
    "cfg_pyshark_limit": 200000,
    "cfg_osint_top_ips": 50,
    "cfg_osint_cache_enabled": False,  # Enable/disable OSINT response caching
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
    """
    Manage application configuration with persistence and encryption.

    Sensitive values (API keys) are encrypted using Fernet symmetric encryption
    derived from a machine-specific key.
    """

    # Legacy static salt for backward compatibility with existing configs
    _LEGACY_SALT = b"pcap_hunter_v1_salt"

    def __init__(self, config_path: str | Path | None = None):
        """
        Initialize the config manager.

        Args:
            config_path: Path to config file. Defaults to ~/.pcap_hunter_config.json
        """
        if config_path is None:
            config_path = Path.home() / ".pcap_hunter_config.json"
        self.config_path = Path(config_path)
        self._salt = self._load_or_create_salt()
        self._fernet = self._create_fernet(self._salt)
        self.defaults = DEFAULT_CONFIG.copy()

    def _load_or_create_salt(self) -> bytes:
        """Load salt from existing config or generate a new one.

        On first run (no config file), generates a random 16-byte salt.
        On subsequent runs, reads the stored salt from the config JSON.
        Falls back to legacy static salt for configs that lack a stored salt.
        """
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                salt_b64 = saved.get("_salt")
                if salt_b64:
                    return base64.b64decode(salt_b64)
                # Existing config without _salt — use legacy salt for backward compatibility
                return self._LEGACY_SALT
            except (json.JSONDecodeError, IOError):
                return self._LEGACY_SALT
        # New config — generate random salt
        return os.urandom(16)

    def _create_fernet(self, salt: bytes) -> Fernet:
        """Create Fernet instance with machine-derived key."""
        # Use machine-specific identity (hostname + username)
        # platform.node() is cross-platform (works on Windows, macOS, Linux)
        machine_id = f"{os.getenv('USER', os.getenv('USERNAME', 'user'))}@{platform.node()}".encode()

        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(machine_id))
        return Fernet(key)

    def _encrypt(self, value: str) -> str:
        """Encrypt a sensitive value."""
        if not value:
            return ""
        encrypted = self._fernet.encrypt(value.encode())
        return f"ENC[{encrypted.decode()}]"

    def _decrypt(self, value: str) -> str:
        """Decrypt a sensitive value."""
        if not value or not value.startswith("ENC["):
            return value
        try:
            encrypted = value[4:-1]  # Remove "ENC[" and "]"
            return self._fernet.decrypt(encrypted.encode()).decode()
        except Exception as e:
            logger.warning("config operation failed: %s", e)
            return ""  # Return empty on decryption failure

    def load(self) -> dict[str, Any]:
        """
        Load configuration from file.

        Returns:
            Configuration dict merged with defaults
        """
        config = self.defaults.copy()

        if not self.config_path.exists():
            return config

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                saved = json.load(f)

            # Merge saved values with defaults
            for key, value in saved.items():
                if key == "_salt":
                    continue  # Internal key, not exposed in config
                if key in SENSITIVE_KEYS:
                    config[key] = self._decrypt(value)
                else:
                    config[key] = value

        except (json.JSONDecodeError, IOError):
            # Return defaults on error
            pass

        return config

    def save(self, config: dict[str, Any]) -> None:
        """
        Save configuration to file with secure permissions.

        Args:
            config: Configuration dict to save

        Raises:
            IOError: If file cannot be written
            TypeError: If config is not a dictionary
        """
        if not isinstance(config, dict):
            raise TypeError("Config must be a dictionary")

        to_save = {}

        # Persist the salt so it can be loaded on next run
        to_save["_salt"] = base64.b64encode(self._salt).decode("ascii")

        for key, value in config.items():
            if key == "_salt":
                continue  # Skip user-supplied _salt; we manage it internally
            if key in SENSITIVE_KEYS:
                to_save[key] = self._encrypt(str(value) if value else "")
            else:
                to_save[key] = value

        try:
            # Write to file
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(to_save, f, indent=2)

            # Set secure permissions (owner read/write only) - Unix only
            try:
                os.chmod(self.config_path, 0o600)
            except (OSError, AttributeError):
                pass  # Ignore on Windows or if chmod fails

        except IOError as e:
            raise IOError(f"Failed to save config: {e}") from e

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a single configuration value.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        config = self.load()
        return config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """
        Set a single configuration value.

        Args:
            key: Configuration key
            value: Value to set
        """
        config = self.load()
        config[key] = value
        self.save(config)

    def clear(self) -> None:
        """Delete the configuration file."""
        if self.config_path.exists():
            self.config_path.unlink()


# Global instance for convenience
_config_manager: ConfigManager | None = None


def get_config_manager(config_path: str | Path | None = None) -> ConfigManager:
    """Get or create the global config manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager
