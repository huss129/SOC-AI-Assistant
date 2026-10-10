import os, requests, urllib3
urllib3.disable_warnings()

INDEXER = os.environ.get("WAZUH_INDEXER", "https://localhost:9200")
USER = os.environ.get("WAZUH_USER", "admin")
PASSWORD = os.environ.get("WAZUH_PASS", "")

def fetch_alerts(size=500, min_level=0):
    body = {
        "size": size,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"range": {"rule.level": {"gte": min_level}}},
    }
    r = requests.post(f"{INDEXER}/wazuh-alerts-*/_search",
                      json=body, auth=(USER, PASSWORD),
                      verify=False, timeout=30)
    r.raise_for_status()
    out = []
    for h in r.json()["hits"]["hits"]:
        a = h["_source"]
        out.append({
            "time": a.get("timestamp"),
            "level": a["rule"]["level"],
            "rule_id": a["rule"]["id"],
            "description": a["rule"]["description"],
            "mitre": a["rule"].get("mitre", {}).get("technique", []),
            "agent": a.get("agent", {}).get("name"),
            "srcip": a.get("data", {}).get("srcip"),
            "srcuser": a.get("data", {}).get("srcuser"),
            "fired": a["rule"].get("firedtimes"),
            "full_log": a.get("full_log", ""),
        })
    return out
