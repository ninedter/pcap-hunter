"""Tests for OSINT caching functionality."""

import time

import pytest

from app.pipeline.osint_cache import OSINTCache


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary database path."""
    return tmp_path / "test_osint.db"


@pytest.fixture
def cache(temp_db):
    """Create an OSINTCache instance with temp database."""
    return OSINTCache(temp_db, ttl_hours=24)


class TestOSINTCacheBasic:
    def test_cache_miss(self, cache):
        """Query uncached indicator returns None."""
        result = cache.get("8.8.8.8", "greynoise")
        assert result is None

    def test_cache_hit(self, cache):
        """Query cached indicator returns data."""
        test_data = {"classification": "benign", "seen": True}
        cache.set("8.8.8.8", "greynoise", test_data)

        result = cache.get("8.8.8.8", "greynoise")
        assert result == test_data

    def test_case_insensitive(self, cache):
        """Indicators are case-insensitive."""
        cache.set("Example.COM", "vt", {"result": "clean"})

        assert cache.get("example.com", "vt") is not None
        assert cache.get("EXAMPLE.COM", "vt") is not None

    def test_provider_isolation(self, cache):
        """Different providers are isolated."""
        cache.set("8.8.8.8", "greynoise", {"provider": "greynoise"})
        cache.set("8.8.8.8", "vt", {"provider": "vt"})

        gn = cache.get("8.8.8.8", "greynoise")
        vt = cache.get("8.8.8.8", "vt")

        assert gn["provider"] == "greynoise"
        assert vt["provider"] == "vt"


class TestOSINTCacheExpiry:
    def test_ttl_expiration(self, temp_db):
        """Expired entries are not returned."""
        # Create cache with 1 second TTL
        cache = OSINTCache(temp_db, ttl_hours=0)  # 0 hours = immediate expiry
        cache.ttl_seconds = 1  # Override to 1 second

        cache.set("8.8.8.8", "greynoise", {"test": True})

        # Should be available immediately
        assert cache.get("8.8.8.8", "greynoise") is not None

        # Wait for expiry
        time.sleep(1.5)

        # Should be expired
        assert cache.get("8.8.8.8", "greynoise") is None

    def test_cleanup_expired(self, temp_db):
        """Cleanup removes expired entries."""
        cache = OSINTCache(temp_db, ttl_hours=0)
        cache.ttl_seconds = 1

        cache.set("8.8.8.8", "gn", {"test": True})
        cache.set("1.1.1.1", "gn", {"test": True})

        time.sleep(1.5)

        removed = cache.cleanup_expired()
        assert removed == 2


class TestOSINTCacheInvalidation:
    def test_invalidate_single(self, cache):
        """Invalidate specific indicator."""
        cache.set("8.8.8.8", "greynoise", {"test": True})
        cache.set("1.1.1.1", "greynoise", {"test": True})

        count = cache.invalidate("8.8.8.8")
        assert count == 1

        assert cache.get("8.8.8.8", "greynoise") is None
        assert cache.get("1.1.1.1", "greynoise") is not None

    def test_invalidate_provider(self, cache):
        """Invalidate all entries for a provider."""
        cache.set("8.8.8.8", "greynoise", {"test": True})
        cache.set("1.1.1.1", "greynoise", {"test": True})
        cache.set("8.8.8.8", "vt", {"test": True})

        count = cache.invalidate(provider="greynoise")
        assert count == 2

        assert cache.get("8.8.8.8", "greynoise") is None
        assert cache.get("8.8.8.8", "vt") is not None

    def test_invalidate_all(self, cache):
        """Invalidate entire cache."""
        cache.set("8.8.8.8", "greynoise", {"test": True})
        cache.set("1.1.1.1", "vt", {"test": True})

        count = cache.invalidate()
        assert count == 2

        assert cache.get("8.8.8.8", "greynoise") is None
        assert cache.get("1.1.1.1", "vt") is None


class TestOSINTCacheKeyInvalidation:
    """Test API key change detection and cache invalidation."""

    def test_first_run_stores_hash(self, cache):
        """First call stores the key hash without invalidating."""
        cache.set("8.8.8.8", "greynoise", {"test": True})
        cache.invalidate_on_key_change("hash_v1")
        # Entry should still be present (no prior hash to compare against)
        assert cache.get("8.8.8.8", "greynoise") is not None

    def test_same_hash_no_invalidation(self, cache):
        """Same hash on subsequent calls does not invalidate."""
        cache.set("8.8.8.8", "greynoise", {"test": True})
        cache.invalidate_on_key_change("hash_v1")
        cache.invalidate_on_key_change("hash_v1")  # Same hash
        assert cache.get("8.8.8.8", "greynoise") is not None

    def test_different_hash_invalidates(self, cache):
        """Changed hash invalidates all cached entries."""
        cache.set("8.8.8.8", "greynoise", {"test": True})
        cache.set("1.1.1.1", "vt", {"other": True})
        cache.invalidate_on_key_change("hash_v1")

        # Change the hash → should invalidate
        cache.invalidate_on_key_change("hash_v2")
        assert cache.get("8.8.8.8", "greynoise") is None
        assert cache.get("1.1.1.1", "vt") is None

    def test_invalidation_allows_fresh_writes(self, cache):
        """After invalidation, new entries can be written and read."""
        cache.invalidate_on_key_change("old_hash")
        cache.set("1.1.1.1", "vt", {"fresh": True})
        cache.invalidate_on_key_change("new_hash")  # Invalidate
        # Old entry gone
        assert cache.get("1.1.1.1", "vt") is None
        # Write new entry with new key
        cache.set("2.2.2.2", "vt", {"new": True})
        assert cache.get("2.2.2.2", "vt") is not None


class TestOSINTCacheStats:
    def test_get_stats(self, cache):
        """Get cache statistics."""
        cache.set("8.8.8.8", "greynoise", {"test": True})
        cache.set("1.1.1.1", "greynoise", {"test": True})
        cache.set("8.8.8.8", "vt", {"test": True})

        stats = cache.get_stats()

        assert stats["total_entries"] == 3
        assert stats["by_provider"]["greynoise"] == 2
        assert stats["by_provider"]["vt"] == 1
        assert stats["ttl_hours"] == 24
        assert stats["db_size_bytes"] > 0


class TestOSINTCacheEdgeCases:
    def test_complex_data(self, cache):
        """Handle complex nested data."""
        complex_data = {
            "data": {
                "attributes": {
                    "reputation": 0,
                    "tags": ["scanner", "cloud"],
                    "nested": {"deep": {"value": 123}},
                }
            },
            "list": [1, 2, 3],
        }
        cache.set("8.8.8.8", "vt", complex_data)

        result = cache.get("8.8.8.8", "vt")
        assert result == complex_data
        assert result["data"]["attributes"]["nested"]["deep"]["value"] == 123

    def test_unicode_data(self, cache):
        """Handle unicode in data."""
        data = {"org": "谷歌公司", "notes": "Test 🔒 security"}
        cache.set("8.8.8.8", "custom", data)

        result = cache.get("8.8.8.8", "custom")
        assert result["org"] == "谷歌公司"
        assert "🔒" in result["notes"]

    def test_overwrite_entry(self, cache):
        """Overwriting updates data."""
        cache.set("8.8.8.8", "greynoise", {"version": 1})
        cache.set("8.8.8.8", "greynoise", {"version": 2})

        result = cache.get("8.8.8.8", "greynoise")
        assert result["version"] == 2

    def test_empty_data(self, cache):
        """Handle empty data dict."""
        cache.set("8.8.8.8", "empty", {})
        result = cache.get("8.8.8.8", "empty")
        assert result == {}


class TestOSINTCacheThreadSafety:
    """Test thread safety of cache operations."""

    def test_concurrent_writes(self, temp_db):
        """Test concurrent write operations don't corrupt database."""
        import concurrent.futures

        cache = OSINTCache(temp_db, ttl_hours=24)
        errors = []

        def write_entry(i):
            try:
                cache.set(f"ip_{i}", "provider", {"index": i})
            except Exception as e:
                errors.append(e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(write_entry, i) for i in range(50)]
            concurrent.futures.wait(futures)

        assert len(errors) == 0, f"Errors occurred: {errors}"

        # Verify entries were written
        for i in range(50):
            result = cache.get(f"ip_{i}", "provider")
            assert result is not None, f"Missing entry for ip_{i}"

    def test_concurrent_reads_writes(self, temp_db):
        """Test concurrent read and write operations."""
        import concurrent.futures
        import random

        cache = OSINTCache(temp_db, ttl_hours=24)

        # Pre-populate some entries
        for i in range(20):
            cache.set(f"ip_{i}", "vt", {"data": i})

        errors = []

        def read_write():
            try:
                for _ in range(10):
                    i = random.randint(0, 19)
                    cache.get(f"ip_{i}", "vt")
                    cache.set(f"ip_{i}", "vt", {"data": i * 2})
            except Exception as e:
                errors.append(e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(read_write) for _ in range(5)]
            concurrent.futures.wait(futures)

        assert len(errors) == 0, f"Errors occurred: {errors}"

    def test_close_connection(self, temp_db):
        """Test close method doesn't raise errors."""
        cache = OSINTCache(temp_db, ttl_hours=24)
        cache.set("8.8.8.8", "test", {"data": "test"})

        # Close should not raise
        cache.close()

        # Operations after close should still work (creates new connection)
        result = cache.get("8.8.8.8", "test")
        assert result is not None
