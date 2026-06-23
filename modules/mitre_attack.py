"""
Maps a detected threat category to a MITRE ATT&CK technique.
Static reference table covering common SOC-relevant techniques
(Enterprise ATT&CK matrix subset most relevant for IOC triage).
"""

MITRE_MAP = {
    "malware": {
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "Execution",
    },
    "phishing": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
    },
    "botnet": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
    },
    "c2_server": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols (C2)",
        "tactic": "Command and Control",
    },
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "none": {
        "technique_id": "-",
        "technique_name": "No malicious activity detected",
        "tactic": "-",
    },
    "unknown": {
        "technique_id": "-",
        "technique_name": "Unclassified",
        "tactic": "-",
    },
}


def map_to_mitre(threat_category):
    return MITRE_MAP.get(threat_category, MITRE_MAP["unknown"])
