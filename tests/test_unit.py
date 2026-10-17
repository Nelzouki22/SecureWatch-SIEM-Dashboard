from datetime import datetime
import siem_engine, brute_force_detector, password_generator, alert_engine

def test_normalize_severity_and_type():
    rec = {"event_id": 4625, "timestamp": "2026-10-15T08:17:33", "username": "admin", "source_ip": "1.2.3.4"}
    n = siem_engine.normalize(rec, "windows")
    assert n["event_type"] == "Failed Login"
    assert n["severity"] in ("Information","Warning","Medium","High","Critical")
    assert isinstance(n["timestamp"], datetime)

def test_parse_windows_message_extracts_user_and_ip():
    recs = [{
        "EventID": 4625,
        "TimeCreated": "2026-10-15T08:00:00",
        "Message": "An account failed to log on.\nAccount Name:\tadmin\nSource Network Address:\t9.9.9.9"
    }]
    import json, tempfile, os
    p = tempfile.mktemp(suffix=".json")
    open(p, "w").write(json.dumps(recs))
    out = siem_engine.parse_windows_evtx_like(p)
    assert out[0]["username"] == "admin"
    assert out[0]["source_ip"] == "9.9.9.9"

def test_brute_force_detector_threshold():
    events = [{"event_type": "Failed Login", "source_ip": "5.5.5.5", "username": "root"} for _ in range(6)]
    alerts = brute_force_detector.detect_brute_force(events, threshold=5)
    assert len(alerts) == 1
    assert alerts[0]["count"] >= 5
    assert alerts[0]["severity"] == "Critical"

def test_password_generator_strength():
    pw = password_generator.generate(16)
    assert any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
    assert len(pw) == 16

def test_security_score_bounds(db):
    score = alert_engine.security_score()
    assert 0 <= score <= 100