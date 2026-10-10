import sys, json, time, random, csv
from collections import defaultdict
from parse_alerts import load_alerts
import analyze

MODEL = sys.argv[1] if len(sys.argv) > 1 else "qwen2.5:1.5b"
PER_RULE = 4
analyze.MODEL = MODEL
truth = json.load(open("truth.json"))

by_rule = defaultdict(list)
for a in load_alerts():
    if a["rule_id"] in truth:
        by_rule[a["rule_id"]].append(a)

random.seed(7)
sample = []
for rid in sorted(by_rule):
    items = by_rule[rid]
    sample += random.sample(items, min(PER_RULE, len(items)))

print(f"Model: {MODEL} | Alerts: {len(sample)} (no code rules)")
rows, errors = [], defaultdict(int)
correct = fp = fn = 0
t_all = []
for i, a in enumerate(sample, 1):
    t0 = time.time()
    try:
        r = analyze.analyze_with_model(a)   # النموذج لوحده
        pred = "threat" if r["is_likely_threat"] else "noise"
        cat = r["category"]
    except Exception as e:
        pred, cat = "error", str(e)[:40]
    dt = time.time() - t0
    t_all.append(dt)
    t = truth[a["rule_id"]]
    ok = pred == t
    correct += ok
    fp += (pred == "threat" and t == "noise")
    fn += (pred == "noise" and t == "threat")
    if not ok:
        errors[(a["rule_id"], a["description"][:40], t, cat)] += 1
    rows.append([a["rule_id"], a["level"], t, pred, cat, round(dt, 1)])
    print(f"[{i}/{len(sample)}] {a['rule_id']} truth={t} pred={pred} cat={cat} ({dt:.1f}s)")

n = len(sample)
print("\n==== RESULT ====")
print(f"Accuracy: {correct}/{n} = {correct/n:.0%}")
print(f"False positives: {fp} | False negatives: {fn}")
print(f"Avg time: {sum(t_all)/n:.1f}s")
print("\nErrors by rule (rule, desc, truth, model category) -> count")
for k, v in sorted(errors.items(), key=lambda x: -x[1]):
    print(v, k)

out = f"eval2_{MODEL.replace(':','_')}.csv"
with open(out, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["rule_id", "level", "truth", "pred", "category", "seconds"])
    w.writerows(rows)
print("saved", out)
