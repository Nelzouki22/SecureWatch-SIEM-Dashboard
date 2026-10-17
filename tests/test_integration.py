def _register(client):
    return client.post("/register", data={"username": "tester", "email": "t@e.com", "password": "Passw0rd!"}, follow_redirects=True)

def _login(client, u="tester", p="Passw0rd!"):
    return client.post("/login", data={"username": u, "password": p}, follow_redirects=True)

def test_register_login_logout_flow(client):
    r = _register(client)
    assert b"SecureWatch" in r.data
    r = _login(client)
    assert b"Dashboard" in r.data or b"dashboard" in r.url.lower()
    r = client.get("/logout", follow_redirects=True)
    assert b"Sign In" in r.data or b"Login" in r.data

def test_dashboard_requires_auth(client):
    r = client.get("/dashboard", follow_redirects=True)
    assert b"Sign In" in r.data or "/login" in r.request.path

def test_events_search_and_ingest_sample(client):
    _register(client)
    _login(client)
    r = client.get("/events?severity=Critical")
    assert r.status_code == 200
    r = client.get("/ingest/sample/sample_logs.json", follow_redirects=True)
    assert r.status_code == 200

def test_alert_detection_endpoint(client):
    _register(client)
    _login(client)
    client.get("/ingest/sample/windows_security_logs.json", follow_redirects=True)
    r = client.post("/alerts/run-detection", follow_redirects=True)
    assert r.status_code == 200

def test_incident_create_view_update(client):
    _register(client)
    _login(client)
    r = client.post("/incidents/new", data={"title": "Test INC", "severity": "High", "assigned_to": "SOC"}, follow_redirects=True)
    assert b"INC-" in r.data
    r = client.get("/incidents")
    assert r.status_code == 200

def test_reports_export_pdf_csv(client):
    _register(client)
    _login(client)
    r = client.get("/reports/daily/pdf")
    assert r.status_code == 200 and r.mimetype == "application/pdf"
    r = client.get("/reports/weekly/csv")
    assert r.status_code == 200 and r.mimetype == "text/csv"

def test_settings_and_language_switch(client):
    _register(client)
    _login(client)
    r = client.get("/set_lang/ar", follow_redirects=True)
    assert r.status_code == 200
    r = client.get("/settings")
    assert r.status_code == 200

def test_audit_logs_page(client):
    _register(client)
    _login(client)
    r = client.get("/audit")
    assert r.status_code == 200 and b"Audit" in r.data