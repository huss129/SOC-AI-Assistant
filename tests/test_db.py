import db, pytest

def al(rid="5710", log="x"):
    return {"time": "2026-10-10T10:00:00.000+0000", "rule_id": rid, "level": 5,
            "description": "d", "full_log": log}

@pytest.fixture(autouse=True)
def tmpdb(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB", str(tmp_path / "t.db"))

def result():
    return {"category": "auth_failure", "is_likely_threat": True, "severity": "low",
            "decided_by": "model+rule", "summary": "s", "timeline": "",
            "next_steps": ["a"], "evidence": "x"}

def test_save_then_done():
    a = al()
    db.save(a, result())
    assert db.alert_key(a) in db.done_keys()
    assert db.alert_key(a) not in db.retryable_keys()

def test_failure_is_retryable_and_counts():
    a = al()
    db.save_failure(a, "boom")
    assert db.alert_key(a) in db.retryable_keys()
    assert db.alert_key(a) not in db.done_keys()

def test_failure_stops_after_max_attempts():
    a = al()
    for _ in range(db.MAX_ATTEMPTS):
        db.save_failure(a, "boom")
    assert db.alert_key(a) not in db.retryable_keys()
    assert db.alert_key(a) in db.done_keys()

def test_success_after_failure_clears_status():
    a = al()
    db.save_failure(a, "boom")
    db.save(a, result())
    assert db.alert_key(a) in db.done_keys()

def test_failed_row_defaults_to_threat_not_safe():
    a = al()
    db.save_failure(a, "boom")
    row = [r for r in db.load_all() if r["alert_key"] == db.alert_key(a)][0]
    assert row["is_threat"] == 1 and row["status"] == "failed"

def test_migration_keeps_old_rows(tmp_path, monkeypatch):
    import sqlite3
    path = str(tmp_path / "old.db")
    c = sqlite3.connect(path)
    c.execute("""CREATE TABLE analysis (alert_key TEXT PRIMARY KEY, time TEXT, rule_id TEXT,
        level INTEGER, description TEXT, category TEXT, is_threat INTEGER, severity TEXT,
        decided_by TEXT, summary TEXT, timeline TEXT, next_steps TEXT, evidence TEXT)""")
    c.execute("INSERT INTO analysis (alert_key, rule_id) VALUES ('k','5710')")
    c.commit(); c.close()
    monkeypatch.setattr(db, "DB", path)
    rows = db.load_all()
    assert len(rows) == 1 and rows[0]["status"] == "done"
