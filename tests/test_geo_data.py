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
