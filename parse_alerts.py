import json

def load_alerts(path="alerts.json"):
    alerts = []
    with open(path) as f:
        for line in f:
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue
            alerts.append({
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
    return alerts

if __name__ == "__main__":
    alerts = load_alerts()
    print(f"عدد الـ alerts: {len(alerts)}")
    for a in alerts[-5:]:
        print(a["level"], a["rule_id"], a["description"])
