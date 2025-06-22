import geoip2.database

def get_geo_location(ip: str) -> dict:
    try:
        mmdb_path = "C:/GeoIP/data/GeoLite2-City.mmdb"
        print("📍 강제 경로:", mmdb_path)

        reader = geoip2.database.Reader(mmdb_path)
        response = reader.city(ip)

        country = response.country.name
        lat = response.location.latitude
        lon = response.location.longitude

        return {
            "country": country,
            "latitude": lat,
            "longitude": lon
        }

    except Exception as e:
        print("❌ GeoIP 실패:", e)
        return {
            "country": "unknown",
            "latitude": None,
            "longitude": None
        }
