import csv, sys, time, random
from collections import defaultdict
from parse_alerts import load_alerts
import analyze

N_PER_RULE = 3
MAX_TOTAL = 20
OUT = "results.csv"
THREAT_RULES = {"2502","5710","5712","5503","5557","5401","5902"}

def pick_alerts():
    by_rule = defaultdict(list)
    for a in load_alerts():
        by_rule[a["rule_id"]].append(a)
    random.seed(7)
    picked = []
    for rule_id in sorted(by_rule):
        items = by_rule[rule_id]
        picked += random.sample(items, min(N_PER_RULE, len(items)))
    random.shuffle(picked)
    return picked[:MAX_TOTAL]

def run():
    alerts = pick_alerts()
    print(f"Evaluating {len(alerts)} alerts with {analyze.MODEL}")
    rows = []
    for i, a in enumerate(alerts, 1):
        t0 = time.time()
        try:
            r = analyze.analyze(a)
            err = ""
        except Exception as e:
            r, err = {}, str(e)[:80]
        dt = round(time.time() - t0, 1)
        rows.append({
            "id": i, "rule_id": a["rule_id"], "level": a["level"],
            "description": a["description"], "model": analyze.MODEL,
            "model_threat": r.get("is_likely_threat", ""),
            "summary": r.get("summary", ""),
            "seconds": dt, "error": err,
            "truth": "threat" if a["rule_id"] in THREAT_RULES else "noise",
        })
        print(f"[{i}/{len(alerts)}] rule {a['rule_id']} -> {r.get('is_likely_threat','ERR')} ({dt}s) {err}")
    with open(OUT, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    print("saved", OUT)

def score():
    total = correct = fp = fn = 0
    times = []
    with open(OUT, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if row["error"]:
                continue
            truth = row["truth"].strip().lower()
            pred = "threat" if str(row["model_threat"]).lower() == "true" else "noise"
            total += 1
            correct += pred == truth
            fp += (pred == "threat" and truth == "noise")
            fn += (pred == "noise" and truth == "threat")
            times.append(float(row["seconds"]))
    if not total:
        print("no valid rows")
        return
    print(f"Accuracy: {correct}/{total} = {correct/total:.0%}")
    print(f"False positives: {fp}")
    print(f"False negatives: {fn}")
    print(f"Avg time: {sum(times)/len(times):.1f}s")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "score":
        score()
    else:
        run()
