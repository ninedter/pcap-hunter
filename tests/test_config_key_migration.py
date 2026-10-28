"""Protected config keys must migrate without silently losing credentials."""

import base64
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.utils.config_manager import ConfigManager


def test_legacy_ciphertext_is_atomically_migrated_and_survives_host_change(tmp_path, monkeypatch):
    monkeypatch.setenv("USER", "legacy-user")
    monkeypatch.setattr("app.utils.config_manager.platform.node", lambda: "legacy-host")
    salt = b"migration-fixture"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    old = Fernet(base64.urlsafe_b64encode(kdf.derive(b"legacy-user@legacy-host")))
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps(
            {
                "_salt": base64.b64encode(salt).decode(),
                "cfg_vt_key": "ENC[" + old.encrypt(b"dummy-credential").decode() + "]",
                "cfg_llm_model": "saved-model",
            }
        )
    )
    manager = ConfigManager(path)
    assert manager.load()["cfg_vt_key"] == "dummy-credential"
    assert "ENC2[" in path.read_text() and "dummy-credential" not in path.read_text()
    monkeypatch.setattr("app.utils.config_manager.platform.node", lambda: "new-host")
    monkeypatch.setenv("USER", "new-user")
    assert ConfigManager(path).load()["cfg_vt_key"] == "dummy-credential"
    assert ConfigManager(path).load()["cfg_llm_model"] == "saved-model"
    assert manager.key_path.stat().st_mode & 0o777 == 0o600
    assert path.stat().st_mode & 0o777 == 0o600


def test_copy_of_settings_does_not_contain_its_decryption_secret(tmp_path):
    path = tmp_path / "settings.json"
    manager = ConfigManager(path)
    manager.save({"cfg_vt_key": "dummy"})
    saved = path.read_bytes()
    manager.key_path.unlink()
    with pytest.raises(ValueError, match="key is missing"):
        ConfigManager(path)
    assert path.read_bytes() == saved


def test_wrong_injected_key_never_clears_saved_values(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    ConfigManager(path).save({"cfg_vt_key": "dummy"})
    before = path.read_bytes()
    monkeypatch.setenv("PCAP_HUNTER_CONFIG_KEY", Fernet.generate_key().decode())
    with pytest.raises(ValueError, match="cannot be decrypted"):
        ConfigManager(path).load()
    assert path.read_bytes() == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permissions")
def test_public_key_file_is_rejected(tmp_path):
    manager = ConfigManager(tmp_path / "settings.json")
    manager.key_path.chmod(0o644)
    with pytest.raises(ValueError, match="mode 0600"):
        ConfigManager(manager.config_path)


def test_concurrent_writers_preserve_independent_updates(tmp_path):
    path = tmp_path / "settings.json"
    ConfigManager(path).save({"cfg_vt_key": "dummy"})
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda i: ConfigManager(path).set("field_" + str(i), i), range(12)))
    values = ConfigManager(path).load()
    assert values["cfg_vt_key"] == "dummy"
    assert all(values["field_" + str(i)] == i for i in range(12))


def test_plaintext_legacy_key_migrates_without_creating_weak_backup(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"cfg_vt_key": "legacy-dummy"}))
    assert ConfigManager(path).load()["cfg_vt_key"] == "legacy-dummy"
    assert all("legacy-dummy" not in f.read_text() for f in tmp_path.iterdir() if f.is_file())
