from __future__ import annotations

from functools import lru_cache
from typing import Any

from geolite2 import geolite2


class GeoIP:
    _reader = None

    @classmethod
    def get_reader(cls):
        if cls._reader is None:
            cls._reader = geolite2.reader()
        return cls._reader

    @staticmethod
    @lru_cache(maxsize=4096)
    def _lookup_cached(ip: str) -> tuple | None:
        """Internal cached lookup returning a tuple (hashable for lru_cache)."""
        try:
            reader = GeoIP.get_reader()
            match = reader.get(ip)
            if not match:
                return None

            country = match.get("country", {}).get("names", {}).get("en", "Unknown")
            city = match.get("city", {}).get("names", {}).get("en", "Unknown")
            loc = match.get("location", {})
            lat = loc.get("latitude")
            lon = loc.get("longitude")

            if lat is None or lon is None:
                return None

            return (ip, country, city, lat, lon)
        except Exception:
            return None

    @classmethod
    def lookup(cls, ip: str) -> dict[str, Any] | None:
        result = cls._lookup_cached(ip)
        if result is None:
            return None
        return {"ip": result[0], "country": result[1], "city": result[2], "lat": result[3], "lon": result[4]}

    @classmethod
    def close(cls):
        if cls._reader:
            geolite2.close()
            cls._reader = None
            cls._lookup_cached.cache_clear()
