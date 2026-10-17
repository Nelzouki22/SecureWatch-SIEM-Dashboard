import json
from datetime import datetime
from models import db, Incident
import audit_logger

def next_incident_id():
    last = Incident.query.order_by(Incident.id.desc()).first()
    n = (int(last.incident_id.split("-")[1]) + 1) if last and "-" in last.incident_id else 1001
    return f"INC-{n}"

def create(title, severity="Medium", assigned_to="", description="", notes="", incident_id=None):
    inc = Incident(
        incident_id=incident_id or next_incident_id(),
        title=title, severity=severity, status="Open",
        assigned_to=assigned_to, description=description, notes=notes
    )
    db.session.add(inc)
    db.session.commit()
    audit_logger.record("CREATE_INCIDENT", f"{inc.incident_id}: {title}")
    return inc

def update_status(incident_id, status, note=""):
    inc = Incident.query.get(incident_id)
    if not inc: return None
    old = inc.status
    inc.status = status
    if status in ("Resolved","Closed"):
        inc.resolved_at = datetime.utcnow()
    if note:
        inc.notes = (inc.notes or "") + f"\n[{datetime.utcnow():%Y-%m-%d %H:%M}] {status}: {note}"
    db.session.commit()
    audit_logger.record("UPDATE_INCIDENT", f"{inc.incident_id}: {old}->{status}")
    return inc

def add_note(incident_id, note):
    inc = Incident.query.get(incident_id)
    if not inc: return None
    inc.notes = (inc.notes or "") + f"\n[{datetime.utcnow():%Y-%m-%d %H:%M}] {note}"
    db.session.commit()
    audit_logger.record("ADD_NOTE", f"{inc.incident_id}")
    return inc

def seed_from_json(path):
    data = json.load(open(path, encoding="utf-8"))
    made = 0
    for d in data:
        if not Incident.query.filter_by(incident_id=d["incident_id"]).first():
            db.session.add(Incident(
                incident_id=d["incident_id"],
                title=d["title"],
                severity=d["severity"],
                status=d.get("status", "Open"),
                assigned_to=d.get("assigned_to", ""),
                description=d.get("description", "")
            ))
            made += 1
    db.session.commit()
    return made