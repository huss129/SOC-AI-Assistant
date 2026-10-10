import json, sys, time
from collections import Counter
import analyze

MODEL = sys.argv[1] if len(sys.argv) > 1 else "qwen2.5:1.5b"
analyze.MODEL = MODEL
labeled = json.load(open("labeled.json"))
all_alerts = [a for a in labeled]   # السياق من نفس الداتا

tp = tn = fp = fn = 0
by = Counter()
errors = []
times = []
for i, a in enumerate(labeled, 1):
    t0 = time.time()
    try:
        r = analyze.analyze(a, all_alerts)
        pred = "threat" if r["is_likely_threat"] else "noise"
        who = r.get("decided_by", "?")
    except Exception as e:
        pred, who = "error", "error"
    dt = time.time() - t0
    times.append(dt)
    truth = a["truth"]
    by[(who, pred == truth)] += 1
    if pred == truth:
        tp += truth == "threat"; tn += truth == "noise"
    else:
        fp += (pred == "threat"); fn += (pred == "noise")
        errors.append((a["rule_id"], truth, pred, who, a["description"][:40]))
    print(f"[{i}/{len(labeled)}] {a['rule_id']} truth={truth} pred={pred} by={who} ({dt:.1f}s)")

n = len(labeled)
print("\n==== FINAL RESULT ====")
print(f"Model: {MODEL}")
print(f"Accuracy: {tp+tn}/{n} = {(tp+tn)/n:.0%}")
print(f"TP={tp} TN={tn} FP={fp} FN={fn}")
if tp + fp: print(f"Precision: {tp/(tp+fp):.0%}")
if tp + fn: print(f"Recall: {tp/(tp+fn):.0%}")
if tp + fp and tp + fn and tp:
    pr, rc = tp / (tp + fp), tp / (tp + fn)
    print(f"F1: {2*pr*rc/(pr+rc):.0%}")
print(f"Sample: {n} alerts ({tp+fn} threat / {tn+fp} noise)")
if tp + fn < 30:
    print("WARNING: fewer than 30 threat samples - treat metrics as indicative only")
print(f"Avg time: {sum(times)/n:.1f}s")
print("\nDecided by (who, correct?) -> count")
for k, v in sorted(by.items()): print(v, k)
print("\nErrors:")
for e in errors: print(e)
