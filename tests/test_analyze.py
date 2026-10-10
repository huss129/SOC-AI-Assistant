import analyze, requests, pytest

class R:
    def __init__(s, c): s.c = c
    def json(s): return {"message": {"content": s.c}}

def al(t, rid, lvl, ip="10.0.0.5", user=None, log="log"):
    return {"time": f"2026-10-10T10:{t}:00.000+0000", "rule_id": rid, "level": lvl,
            "description": "d", "full_log": log, "srcip": ip, "srcuser": user,
            "mitre": [], "agent": "a", "fired": 1}

def fake(monkeypatch, content):
    monkeypatch.setattr(requests, "post", lambda *a, **k: R(content))

@pytest.mark.parametrize("bad", ["not json", "[1,2]", '{"summary":"x"}'])
def test_bad_model_output_rejected(monkeypatch, bad):
    fake(monkeypatch, bad)
    with pytest.raises(ValueError):
        analyze.analyze_with_model(al("00", "9999", 7), None)

def test_invented_evidence_replaced(monkeypatch):
    fake(monkeypatch, '{"category":"auth_failure","summary":"s","evidence":"INVENTED","next_steps":"x"}')
    r = analyze.analyze_with_model(al("00", "9999", 7, log="real log"), None)
    assert r["evidence"] == "real log"
    assert r["next_steps"] == ["x"]

def test_unknown_category_is_threat(monkeypatch):
    fake(monkeypatch, '{"category":"made_up","summary":"s","evidence":"log","next_steps":[]}')
    r = analyze.analyze_with_model(al("00", "9999", 7), None)
    assert r["is_likely_threat"] is True

def test_severity_from_level():
    assert analyze.severity_from_level(5) == "low"
    assert analyze.severity_from_level(10) == "medium"
    assert analyze.severity_from_level(12) == "high"
    assert analyze.severity_from_level(15) == "critical"

def test_success_after_failures_is_threat():
    fails = [al(f"0{i}", "5710", 5) for i in range(4)]
    ok = al("05", "5715", 3)
    r = analyze.analyze(ok, fails + [ok])
    assert r["is_likely_threat"] is True

def test_success_unrelated_ip_is_noise():
    fails = [al(f"0{i}", "5710", 5) for i in range(4)]
    r = analyze.analyze(al("05", "5715", 3, ip="10.9.9.9"), fails)
    assert r["is_likely_threat"] is False

def test_low_level_near_failures_not_hidden(monkeypatch):
    fake(monkeypatch, '{"category":"auth_failure","summary":"s","evidence":"log","next_steps":[]}')
    fails = [al(f"0{i}", "5710", 5) for i in range(4)]
    r = analyze.analyze(al("05", "5502", 3), fails)
    assert r["is_likely_threat"] is True

def test_loopback_not_linked():
    lo = [al(f"0{i}", "5710", 5, ip="::1") for i in range(3)]
    assert analyze.recent_auth_failures(al("05", "5715", 3, ip="::1"), lo) == 0

def test_sca_is_config_assessment():
    a = al("00", "19007", 7)
    a["description"] = "CIS Distribution Independent Linux Benchmark: Ensure SSH x"
    r = analyze.analyze(a, None)
    assert r["category"] == "config_assessment" and r["is_likely_threat"] is False

def test_dpkg_is_noise():
    a = al("00", "2902", 7)
    a["description"] = "New dpkg (Debian Package) installed."
    r = analyze.analyze(a, None)
    assert r["category"] == "package_change" and r["is_likely_threat"] is False

def fim(path, rid="550", t="05"):
    a = al(t, rid, 7, log=f"File '{path}' modified\nMode: scheduled")
    a["description"] = "Integrity checksum changed."
    return a

def test_fim_sensitive_is_threat_even_with_package_activity():
    pkg = al("04", "2902", 7)
    r = analyze.analyze(fim("/etc/shadow"), [pkg])
    assert r["is_likely_threat"] is True

def test_fim_binary_with_package_activity_is_noise():
    pkg = al("04", "2902", 7)
    r = analyze.analyze(fim("/usr/bin/figlet", "553"), [pkg])
    assert r["is_likely_threat"] is False

def test_fim_binary_without_package_activity_is_threat():
    r = analyze.analyze(fim("/usr/bin/figlet"), [])
    assert r["is_likely_threat"] is True
