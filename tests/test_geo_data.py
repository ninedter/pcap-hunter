from app.utils import geo_data


def test_load_geo_data():
    """Verify data is loaded correctly."""
    data = geo_data.load_geo_data()
    assert isinstance(data, list)
    assert len(data) > 0
    # Check structure of first item
    item = data[0]
    assert "n" in item  # name
    assert "lt" in item  # lat
    assert "ln" in item  # lon
    assert "cn" in item  # country name
    assert "ct" in item  # continent


def test_get_continents():
    """Verify unique continents are returned."""
    continents = geo_data.get_continents()
    assert isinstance(continents, list)
    assert len(continents) > 0
    assert "Europe" in continents
    assert "Asia" in continents


def test_get_countries_by_continent():
    """Verify countries are filtered by continent."""
    countries = geo_data.get_countries("Europe")
    assert isinstance(countries, list)
    assert len(countries) > 0
    # AD is Andorra, which should be in Europe
    assert "Andorra" in countries


def test_get_cities_by_country():
    """Verify cities are filtered by country."""
    cities = geo_data.get_cities("Andorra")
    assert isinstance(cities, list)
    assert len(cities) > 0
    assert "Andorra la Vella" in cities


def test_get_location_details():
    """Verify coordinates are retrieved correctly."""
    lat, lon = geo_data.get_location_details("Andorra la Vella", "Andorra")
    assert isinstance(lat, float)
    assert isinstance(lon, float)
    assert lat != 0.0
    assert lon != 0.0

    # Test non-existent
    lat, lon = geo_data.get_location_details("NonExistentCity", "NoCountry")
    assert lat == 0.0
    assert lon == 0.0


def test_geo_index_builds_once(monkeypatch):
    records = [
        {"n": "City A", "lt": 1.0, "ln": 2.0, "cn": "Country A", "ct": "Continent A"},
        {"n": "City B", "lt": 3.0, "ln": 4.0, "cn": "Country A", "ct": "Continent A"},
    ]
    calls = 0

    def fake_load():
        nonlocal calls
        calls += 1
        return records

    geo_data._geo_index.cache_clear()
    monkeypatch.setattr(geo_data, "load_geo_data", fake_load)
    try:
        assert geo_data.get_continents() == ["Continent A"]
        assert geo_data.get_countries("Continent A") == ["Country A"]
        assert geo_data.get_cities("Country A") == ["City A", "City B"]
        assert geo_data.get_location_details("City B", "Country A") == (3.0, 4.0)
        assert calls == 1
    finally:
        geo_data._geo_index.cache_clear()
