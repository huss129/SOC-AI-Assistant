import sys, time
import db, wazuh_client, analyze

LOOP = "--loop" in sys.argv
INTERVAL = 60

def run_once():
    try:
        alerts = wazuh_client.fetch_alerts(size=1000)
    except Exception as e:
        print("Wazuh not ready, will retry:", str(e)[:70])
        return
    known = db.done_keys()
    new = [a for a in alerts if db.alert_key(a) not in known]
    print(f"{len(alerts)} alerts | {len(new)} new")
    for i, a in enumerate(new, 1):
        t0 = time.time()
        try:
            r = analyze.analyze(a, alerts)
            db.save(a, r)
            print(f"[{i}/{len(new)}] {a['rule_id']} -> {r['category']} "
                  f"({r['decided_by']}, {time.time()-t0:.1f}s)")
        except Exception as e:
            db.save_failure(a, e)
            print(f"[{i}/{len(new)}] {a['rule_id']} FAILED (saved): {str(e)[:60]}")

if __name__ == "__main__":
    run_once()
    while LOOP:
        time.sleep(INTERVAL)
        run_once()
