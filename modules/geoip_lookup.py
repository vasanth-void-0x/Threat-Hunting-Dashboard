"""
GeoIP attacker-location tracking.
Uses ip-api.com (free, no key needed, 45 req/min limit) for live lookups.
Falls back to deterministic mock geo data if the request fails (offline demo,
private/reserved IPs, rate limit, etc.)
"""

import hashlib
import requests

IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org"

MOCK_LOCATIONS = [
    {"country": "Russia", "countryCode": "RU", "city": "Moscow", "lat": 55.75, "lon": 37.61, "isp": "Unknown ISP"},
    {"country": "China", "countryCode": "CN", "city": "Shanghai", "lat": 31.23, "lon": 121.47, "isp": "Unknown ISP"},
    {"country": "United States", "countryCode": "US", "city": "Ashburn", "lat": 39.04, "lon": -77.49, "isp": "Unknown ISP"},
    {"country": "Brazil", "countryCode": "BR", "city": "Sao Paulo", "lat": -23.55, "lon": -46.63, "isp": "Unknown ISP"},
    {"country": "Germany", "countryCode": "DE", "city": "Frankfurt", "lat": 50.11, "lon": 8.68, "isp": "Unknown ISP"},
    {"country": "India", "countryCode": "IN", "city": "Mumbai", "lat": 19.07, "lon": 72.87, "isp": "Unknown ISP"},
    {"country": "Netherlands", "countryCode": "NL", "city": "Amsterdam", "lat": 52.37, "lon": 4.89, "isp": "Unknown ISP"},
]


def _mock_geo(ip):
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    loc = MOCK_LOCATIONS[h % len(MOCK_LOCATIONS)]
    return {**loc, "source": "demo-mode"}


def get_geoip(ip):
    try:
        resp = requests.get(IP_API_URL.format(ip=ip), timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "countryCode": data.get("countryCode"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "source": "ip-api-live",
            }
        return _mock_geo(ip)
    except requests.exceptions.RequestException:
        return _mock_geo(ip)
