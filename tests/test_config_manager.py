"""Tests for configuration persistence manager."""

import pytest

from app import config as C
from app.utils.config_manager import DEFAULT_CONFIG, SENSITIVE_KEYS, ConfigManager


@pytest.fixture
def temp_config_file(tmp_path):
    """Create a temporary config file path."""
    return tmp_path / "test_config.json"


@pytest.fixture
def config_manager(temp_config_file):
    """Create a ConfigManager instance with temp file."""
    return ConfigManager(temp_config_file)


class TestConfigManagerBasic:
    def test_llm_defaults_match_runtime_configuration(self):
        """Fresh installs use the same LM Studio endpoint and model as the runtime."""
        assert DEFAULT_CONFIG["cfg_llm_endpoint"] == C.LM_BASE_URL
        assert DEFAULT_CONFIG["cfg_llm_model"] == C.LM_MODEL

    def test_load_missing_file(self, config_manager):
        """Loading non-existent file returns defaults."""
        config = config_manager.load()
        assert config == DEFAULT_CONFIG

    def test_save_and_load(self, config_manager):
        """Round-trip save and load preserves values."""
        original = {
            "cfg_llm_endpoint": "http://localhost:1234/v1",
            "cfg_llm_model": "test-model",
            "cfg_pyshark_limit": 100000,
        }
        config_manager.save(original)
        loaded = config_manager.load()

        assert loaded["cfg_llm_endpoint"] == original["cfg_llm_endpoint"]
        assert loaded["cfg_llm_model"] == original["cfg_llm_model"]
        assert loaded["cfg_pyshark_limit"] == original["cfg_pyshark_limit"]

    def test_get_single_value(self, config_manager):
        """Get single value from config."""
        config_manager.save({"cfg_llm_endpoint": "http://test:1234"})
        assert config_manager.get("cfg_llm_endpoint") == "http://test:1234"
        assert config_manager.get("nonexistent", "default") == "default"

    def test_set_single_value(self, config_manager):
        """Set single value in config."""
        config_manager.set("cfg_llm_model", "new-model")
        assert config_manager.get("cfg_llm_model") == "new-model"

    def test_clear_config(self, config_manager, temp_config_file):
        """Clear removes config file."""
        config_manager.save({"test": "value"})
        assert temp_config_file.exists()

        config_manager.clear()
        assert not temp_config_file.exists()


class TestConfigEncryption:
    def test_api_keys_encrypted(self, config_manager, temp_config_file):
        """API keys should be encrypted in the file."""
        config_manager.save({"cfg_vt_key": "my_secret_api_key"})

        # Read raw file content
        raw_content = temp_config_file.read_text()

        # Secret should not appear in plaintext
        assert "my_secret_api_key" not in raw_content
        # Should be encrypted
        assert "ENC[" in raw_content

    def test_api_keys_decrypted_on_load(self, config_manager):
        """API keys should be decrypted when loaded."""
        original_key = "super_secret_key_12345"
        config_manager.save({"cfg_vt_key": original_key})

        loaded = config_manager.load()
        assert loaded["cfg_vt_key"] == original_key

    def test_non_sensitive_not_encrypted(self, config_manager, temp_config_file):
        """Non-sensitive values should not be encrypted."""
        config_manager.save(
            {
                "cfg_llm_endpoint": "http://localhost:1234",
                "cfg_pyshark_limit": 50000,
            }
        )

        raw_content = temp_config_file.read_text()
        assert "http://localhost:1234" in raw_content
        assert "50000" in raw_content

    def test_empty_api_key_handling(self, config_manager):
        """Empty API keys should be handled gracefully."""
        config_manager.save({"cfg_vt_key": ""})
        loaded = config_manager.load()
        assert loaded["cfg_vt_key"] == ""

    def test_all_sensitive_keys_encrypted(self, config_manager, temp_config_file):
        """All defined sensitive keys should be encrypted."""
        test_config = {key: f"secret_{key}" for key in SENSITIVE_KEYS}
        config_manager.save(test_config)

        raw_content = temp_config_file.read_text()

        for key in SENSITIVE_KEYS:
            assert f"secret_{key}" not in raw_content


class TestConfigEdgeCases:
    def test_corrupted_json(self, config_manager, temp_config_file):
        """Handle corrupted JSON file gracefully."""
        temp_config_file.write_text("not valid json {{{")
        config = config_manager.load()
        assert config == DEFAULT_CONFIG

    def test_partial_config(self, config_manager):
        """Partial config merges with defaults."""
        config_manager.save({"cfg_llm_endpoint": "http://custom:5000"})
        loaded = config_manager.load()

        # Custom value preserved
        assert loaded["cfg_llm_endpoint"] == "http://custom:5000"
        # Default values still present
        assert "cfg_pyshark_limit" in loaded

    def test_unicode_values(self, config_manager):
        """Handle unicode values correctly."""
        config_manager.save({"cfg_llm_model": "模型名稱-test"})
        loaded = config_manager.load()
        assert loaded["cfg_llm_model"] == "模型名稱-test"

    def test_numeric_values_preserved(self, config_manager):
        """Numeric values maintain their type."""
        config_manager.save(
            {
                "cfg_pyshark_limit": 123456,
                "cfg_osint_top_ips": 100,
            }
        )
        loaded = config_manager.load()
        assert loaded["cfg_pyshark_limit"] == 123456
        assert isinstance(loaded["cfg_pyshark_limit"], int)


class TestConfigIsolation:
    def test_different_paths_isolated(self, tmp_path):
        """Different config paths are independent."""
        cm1 = ConfigManager(tmp_path / "config1.json")
        cm2 = ConfigManager(tmp_path / "config2.json")

        cm1.save({"cfg_llm_model": "model1"})
        cm2.save({"cfg_llm_model": "model2"})

        assert cm1.get("cfg_llm_model") == "model1"
        assert cm2.get("cfg_llm_model") == "model2"
