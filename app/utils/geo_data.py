import json
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

DATA_PATH = Path(__file__).parent.parent / "assets" / "world_cities.json"


def load_geo_data() -> list[dict]:
    """Load the world cities dataset."""
    if not DATA_PATH.exists():
        return []
    try:
        with DATA_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


@lru_cache(maxsize=1)
def _geo_index() -> tuple[
    tuple[str, ...],
    dict[str, tuple[str, ...]],
    dict[str, tuple[str, ...]],
    dict[tuple[str, str], tuple[float, float]],
]:
    """Build immutable lookup tables once instead of rescanning 150k cities per rerun."""
    countries_by_continent: dict[str, set[str]] = defaultdict(set)
    cities_by_country: dict[str, set[str]] = defaultdict(set)
    locations: dict[tuple[str, str], tuple[float, float]] = {}

    for item in load_geo_data():
        try:
            continent = str(item["ct"])
            country = str(item["cn"])
            city = str(item["n"])
            location = (float(item["lt"]), float(item["ln"]))
        except (KeyError, TypeError, ValueError):
            continue
        countries_by_continent[continent].add(country)
        cities_by_country[country].add(city)
        locations.setdefault((city, country), location)

    countries = {continent: tuple(sorted(values)) for continent, values in countries_by_continent.items()}
    cities = {country: tuple(sorted(values)) for country, values in cities_by_country.items()}
    return tuple(sorted(countries)), countries, cities, locations


def get_continents() -> list[str]:
    """Return a sorted list of unique continents."""
    return list(_geo_index()[0])


def get_countries(continent: str) -> list[str]:
    """Return a sorted list of unique countries in a continent."""
    return list(_geo_index()[1].get(continent, ()))


def get_cities(country: str) -> list[str]:
    """Return a sorted list of unique cities in a country."""
    return list(_geo_index()[2].get(country, ()))


def get_location_details(city_name: str, country_name: str) -> tuple[float, float]:
    """Return lat, lon for a specific city/country pair."""
    return _geo_index()[3].get((city_name, country_name), (0.0, 0.0))
