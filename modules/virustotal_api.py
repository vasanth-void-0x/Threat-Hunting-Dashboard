"""
VirusTotal integration.
Works in two modes:
- LIVE: if VT_API_KEY is set in .env, queries the real VirusTotal v3 API
- DEMO: if no key present, falls back to deterministic mock data so the
  dashboard is fully demoable without burning API quota (VT free tier =
  4 req/min, 500/day)
"""

import os
import hashlib
import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3"

THREAT_CATEGORIES = ["malware", "phishing", "botnet", "brute_force", "port_scan", "c2_server"]


def _classify_verdict(malicious_votes, total_votes):
    if total_votes == 0:
        return "clean"
    ratio = malicious_votes / total_votes
    if ratio >= 0.3:
        return "malicious"
    if ratio > 0:
        return "suspicious"
    return "clean"


def _mock_lookup(ioc):
    """Deterministic mock so the same IOC always returns the same verdict (good for demos/screenshots)."""
    h = int(hashlib.md5(ioc.encode()).hexdigest(), 16)
    total_votes = 70 + (h % 20)
    malicious_votes = h % 25  # skew toward varied verdicts
    category = THREAT_CATEGORIES[h % len(THREAT_CATEGORIES)]
    return {
        "verdict": _classify_verdict(malicious_votes, total_votes),
        "malicious_votes": malicious_votes,
        "total_votes": total_votes,
        "threat_category": category if malicious_votes > 0 else "none",
        "source": "demo-mode (no VT_API_KEY set)",
    }


def _live_lookup(ioc, ioc_type):
    vt_api_key = os.getenv("VT_API_KEY", "")
    endpoint_map = {
        "ip": f"{VT_BASE_URL}/ip_addresses/{ioc}",
        "domain": f"{VT_BASE_URL}/domains/{ioc}",
        "hash": f"{VT_BASE_URL}/files/{ioc}",
    }
    url = endpoint_map.get(ioc_type, endpoint_map["ip"])
    headers = {"x-apikey": vt_api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        # crude category guess from VT tags / popular threat classification
        categories = data["data"]["attributes"].get("popular_threat_classification", {})
        category = categories.get("suggested_threat_label", "unknown") if categories else "unknown"

        return {
            "verdict": _classify_verdict(malicious + suspicious, total),
            "malicious_votes": malicious + suspicious,
            "total_votes": total,
            "threat_category": category,
            "source": "virustotal-live",
        }
    except requests.exceptions.RequestException as e:
        # API down / quota hit / IOC not found -> degrade gracefully to mock
        fallback = _mock_lookup(ioc)
        fallback["source"] = f"virustotal-live-failed ({e.__class__.__name__}), used demo fallback"
        return fallback


def check_ioc(ioc, ioc_type="ip"):
    vt_api_key = os.getenv("VT_API_KEY", "")
    if vt_api_key:
        return _live_lookup(ioc, ioc_type)
    return _mock_lookup(ioc)
