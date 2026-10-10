import sqlite3, json, hashlib

DB = "soc.db"

def conn():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS analysis (
        alert_key TEXT PRIMARY KEY,
        time TEXT, rule_id TEXT, level INTEGER, description TEXT,
        category TEXT, is_threat INTEGER, severity TEXT,
        decided_by TEXT, summary TEXT, timeline TEXT,
        next_steps TEXT, evidence TEXT)""")
    cols = {r[1] for r in c.execute("PRAGMA table_info(analysis)")}
    for name, ddl in (("status", "TEXT DEFAULT 'done'"),
                      ("error", "TEXT DEFAULT ''"),
                      ("attempts", "INTEGER DEFAULT 0")):
        if name not in cols:
            c.execute(f"ALTER TABLE analysis ADD COLUMN {name} {ddl}")
    c.commit()
    return c

def alert_key(a):
    raw = f"{a['time']}|{a['rule_id']}|{a['full_log']}"
    return hashlib.sha1(raw.encode()).hexdigest()

def known_keys():
    c = conn()
    keys = {r[0] for r in c.execute("SELECT alert_key FROM analysis")}
    c.close()
    return keys

def save(a, r):
    c = conn()
    c.execute("""INSERT OR REPLACE INTO analysis
        (alert_key,time,rule_id,level,description,category,is_threat,severity,
         decided_by,summary,timeline,next_steps,evidence,status,error,attempts)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'done','',0)""", (
        alert_key(a), a["time"], a["rule_id"], a["level"], a["description"],
        r.get("category"), int(bool(r.get("is_likely_threat"))), r.get("severity"),
        r.get("decided_by"), r.get("summary"), r.get("timeline", ""),
        json.dumps(r.get("next_steps", [])), r.get("evidence", "")))
    c.commit()
    c.close()

def load_all():
    c = conn()
    c.row_factory = sqlite3.Row
    rows = [dict(r) for r in c.execute("SELECT * FROM analysis ORDER BY time DESC")]
    c.close()
    return rows


MAX_ATTEMPTS = 3

def save_failure(a, err):
    c = conn()
    k = alert_key(a)
    row = c.execute("SELECT attempts FROM analysis WHERE alert_key=?", (k,)).fetchone()
    n = (row[0] if row and row[0] else 0) + 1
    if row:
        c.execute("UPDATE analysis SET status='failed', error=?, attempts=? WHERE alert_key=?",
                  (str(err)[:200], n, k))
    else:
        c.execute("""INSERT INTO analysis (alert_key,time,rule_id,level,description,
                     is_threat,status,error,attempts)
                     VALUES (?,?,?,?,?,1,'failed',?,?)""",
                  (k, a["time"], a["rule_id"], a["level"], a["description"],
                   str(err)[:200], n))
    c.commit()
    c.close()

def retryable_keys():
    """alerts فشلت وعدد محاولاتها أقل من الحد"""
    c = conn()
    keys = {r[0] for r in c.execute(
        "SELECT alert_key FROM analysis WHERE status='failed' AND attempts < ?",
        (MAX_ATTEMPTS,))}
    c.close()
    return keys

def done_keys():
    """alerts خلصت، أو فشلت وخلصت محاولاتها (ما نعيدهاش)"""
    c = conn()
    keys = {r[0] for r in c.execute(
        "SELECT alert_key FROM analysis WHERE status IS NULL OR status='done' "
        "OR (status='failed' AND attempts >= ?)", (MAX_ATTEMPTS,))}
    c.close()
    return keys
