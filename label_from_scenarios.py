import json
from datetime import datetime
from collections import Counter
from parse_alerts import load_alerts

scen = json.load(open("scenarios.json"))
for s in scen:
    s["t0"] = datetime.fromisoformat(s["start"]).replace(tzinfo=None)
    s["t1"] = datetime.fromisoformat(s["end"]).replace(tzinfo=None)

def ts(a):
    return datetime.strptime(a["time"][:19], "%Y-%m-%dT%H:%M:%S")

labeled, skipped = [], Counter()
for a in load_alerts():
    t = ts(a)
    for s in scen:
        if not (s["t0"] <= t <= s["t1"]):
            continue
        if s["label"] == "noise":
            labeled.append({**a, "truth": "noise", "scenario": s["name"]})
        elif a["rule_id"] in s["expected_rules"]:      # الحقيقة من تعريف السيناريو
            labeled.append({**a, "truth": "threat", "scenario": s["name"]})
        else:
            skipped[a["rule_id"]] += 1                 # مش متوقعة: تتشال، ما تتعلمش
        break

json.dump(labeled, open("labeled.json", "w"))
c = Counter(x["truth"] for x in labeled)
print(f"labeled={len(labeled)} threat={c['threat']} noise={c['noise']}")
print("skipped (unexpected in attack window):", dict(skipped))
