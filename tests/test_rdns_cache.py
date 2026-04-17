"""Tests for the reverse DNS cache module."""

from __future__ import annotations

import time

import pytest

from app.pipeline.rdns_cache import RDNSCache, get_rdns_cache


@pytest.fixture
def temp_db(tmp_path):
    return tmp_path / "test_rdns.db"


@pytest.fixture
def cache(temp_db):
    c = RDNSCache(temp_db, ttl_hours=24)
    yield c
    c.close()


class TestRDNSCacheBasic:
    def test_cache_miss(self, cache):
        assert cache.get("8.8.8.8") is None

    def test_set_and_get(self, cache):
        cache.set("8.8.8.8", "dns.google")
        assert cache.get("8.8.8.8") == "dns.google"

    def test_overwrite(self, cache):
        cache.set("8.8.8.8", "old.host")
        cache.set("8.8.8.8", "new.host")
        assert cache.get("8.8.8.8") == "new.host"


class TestRDNSCacheBatch:
    def test_get_batch_empty(self, cache):
        assert cache.get_batch([]) == {}

    def test_get_batch_mixed(self, cache):
        cache.set("1.1.1.1", "one.one")
        cache.set("8.8.8.8", "dns.google")
        result = cache.get_batch(["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        assert result == {"1.1.1.1": "one.one", "8.8.8.8": "dns.google"}

    def test_set_batch(self, cache):
        entries = [("1.1.1.1", "one.one"), ("8.8.8.8", "dns.google")]
        cache.set_batch(entries)
        assert cache.get("1.1.1.1") == "one.one"
        assert cache.get("8.8.8.8") == "dns.google"

    def test_set_batch_empty(self, cache):
        cache.set_batch([])  # Should not raise

    def test_get_batch_large(self, cache):
        """Batch get handles > 900 IPs (SQLite placeholder limit)."""
        entries = [(f"10.0.{i // 256}.{i % 256}", f"host-{i}.local") for i in range(1000)]
        cache.set_batch(entries)
        ips = [e[0] for e in entries]
        result = cache.get_batch(ips)
        assert len(result) == 1000


class TestRDNSCacheExpiry:
    def test_ttl_expiration(self, temp_db):
        with RDNSCache(temp_db, ttl_hours=0) as cache:
            cache.ttl_seconds = 1
            cache.set("8.8.8.8", "dns.google")
            assert cache.get("8.8.8.8") is not None
            time.sleep(1.5)
            assert cache.get("8.8.8.8") is None

    def test_cleanup_expired(self, temp_db):
        with RDNSCache(temp_db, ttl_hours=0) as cache:
            cache.ttl_seconds = 1
            cache.set("1.1.1.1", "one.one")
            cache.set("8.8.8.8", "dns.google")
            time.sleep(1.5)
            removed = cache.cleanup_expired()
            assert removed == 2


class TestRDNSCacheEdgeCases:
    def test_close_and_reopen(self, temp_db):
        with RDNSCache(temp_db) as cache:
            cache.set("1.1.1.1", "one.one")
            cache.close()
            # Operations after close should work (reconnects)
            assert cache.get("1.1.1.1") == "one.one"

    def test_corruption_recovery(self, temp_db):
        """Cache recovers from a corrupted database file."""
        temp_db.write_bytes(b"not a database")
        with RDNSCache(temp_db) as cache:
            # After recovery, cache should be usable
            cache.set("1.1.1.1", "one.one")
            assert cache.get("1.1.1.1") == "one.one"


class TestRDNSCacheSingleton:
    def test_get_rdns_cache(self, tmp_path):
        import app.pipeline.rdns_cache as mod

        old = mod._cache
        mod._cache = None
        try:
            c = get_rdns_cache(db_path=tmp_path / "singleton.db")
            assert c is not None
            c2 = get_rdns_cache()
            assert c2 is c
        finally:
            if mod._cache is not None:
                mod._cache.close()
            mod._cache = old
