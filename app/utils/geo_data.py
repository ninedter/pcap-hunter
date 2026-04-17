import json
from pathlib import Path

import streamlit as st

# Path to the data file relative to this file
DATA_PATH = Path(__file__).parent.parent / "assets" / "world_cities.json"


@st.cache_data
def load_geo_data():
    """Load and cache the world cities dataset."""
    if not DATA_PATH.exists():
        return []
    try:
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def get_continents():
    """Return a sorted list of unique continents."""
    data = load_geo_data()
    continents = sorted(list(set(item["ct"] for item in data)))
    return continents


def get_countries(continent):
    """Return a sorted list of unique countries in a continent."""
    data = load_geo_data()
    countries = sorted(list(set(item["cn"] for item in data if item["ct"] == continent)))
    return countries


def get_cities(country):
    """Return a sorted list of unique cities in a country."""
    data = load_geo_data()
    cities = sorted(list(set(item["n"] for item in data if item["cn"] == country)))
    return cities


def get_location_details(city_name, country_name):
    """Return lat, lon for a specific city/country pair."""
    data = load_geo_data()
    for item in data:
        if item["n"] == city_name and item["cn"] == country_name:
            return item["lt"], item["ln"]
    return 0.0, 0.0
