"""
Threat Hunting Dashboard
SOC-style IOC analysis tool: VirusTotal reputation + GeoIP tracking
+ MITRE ATT&CK technique mapping + PDF incident report generation.

Author: Vasanth Kumar
"""

import os
import json
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from dotenv import load_dotenv

load_dotenv()

from modules.virustotal_api import check_ioc
from modules.geoip_lookup import get_geoip
from modules.mitre_attack import map_to_mitre
from modules.pdf_report import generate_pdf_report

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-key-change-me")

DATA_FILE = os.path.join(os.path.dirname(__file__), "sample_data", "investigations.json")


def _load_investigations():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r") as f:
        return json.load(f)


def _save_investigations(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)


@app.route("/")
def index():
    investigations = _load_investigations()
    return render_template("index.html", investigations=investigations)


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Core threat-hunting pipeline:
    1. Take an IOC (IP / domain / file hash)
    2. Pull reputation data from VirusTotal
    3. Resolve GeoIP location (for IPs)
    4. Map detected threat category -> MITRE ATT&CK technique
    5. Persist the investigation record
    """
    payload = request.get_json(force=True)
    ioc = payload.get("ioc", "").strip()
    ioc_type = payload.get("ioc_type", "ip")

    if not ioc:
        return jsonify({"error": "IOC value is required"}), 400

    vt_result = check_ioc(ioc, ioc_type)
    geo_result = get_geoip(ioc) if ioc_type == "ip" else None
    mitre_result = map_to_mitre(vt_result.get("threat_category", "unknown"))

    record = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ioc": ioc,
        "ioc_type": ioc_type,
        "verdict": vt_result.get("verdict"),
        "malicious_votes": vt_result.get("malicious_votes", 0),
        "total_votes": vt_result.get("total_votes", 0),
        "threat_category": vt_result.get("threat_category", "unknown"),
        "geo": geo_result,
        "mitre": mitre_result,
        "source": vt_result.get("source"),
    }

    investigations = _load_investigations()
    investigations.insert(0, record)
    _save_investigations(investigations)

    return jsonify(record)


@app.route("/api/investigations", methods=["GET"])
def list_investigations():
    return jsonify(_load_investigations())


@app.route("/api/investigations/<record_id>", methods=["DELETE"])
def delete_investigation(record_id):
    investigations = _load_investigations()
    investigations = [r for r in investigations if r["id"] != record_id]
    _save_investigations(investigations)
    return jsonify({"status": "deleted"})


@app.route("/api/report/<record_id>", methods=["GET"])
def download_report(record_id):
    investigations = _load_investigations()
    record = next((r for r in investigations if r["id"] == record_id), None)
    if not record:
        return jsonify({"error": "Investigation not found"}), 404

    pdf_path = generate_pdf_report(record)
    return send_file(pdf_path, as_attachment=True, download_name=f"incident_report_{record_id}.pdf")


@app.route("/api/stats", methods=["GET"])
def stats():
    investigations = _load_investigations()
    total = len(investigations)
    malicious = sum(1 for r in investigations if r["verdict"] == "malicious")
    suspicious = sum(1 for r in investigations if r["verdict"] == "suspicious")
    clean = sum(1 for r in investigations if r["verdict"] == "clean")
    countries = {}
    for r in investigations:
        if r.get("geo") and r["geo"].get("country"):
            c = r["geo"]["country"]
            countries[c] = countries.get(c, 0) + 1
    return jsonify({
        "total": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "clean": clean,
        "top_countries": sorted(countries.items(), key=lambda x: -x[1])[:5],
    })


if __name__ == "__main__":
    os.makedirs(os.path.join(os.path.dirname(__file__), "sample_data"), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "reports"), exist_ok=True)
    app.run(debug=True, host="0.0.0.0", port=5000)
