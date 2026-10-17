from collections import defaultdict
from models import db, Event, Alert
import audit_logger

def _existing_key(alert_type, source_ip, username):
    return f"{alert_type}|{source_ip or '-'}|{username or '-'}"

def run_detections(thresholds=None):
    thresholds = thresholds or {}
    bf_thr = int(thresholds.get("brute_force_threshold", 5))
    pe_thr = int(thresholds.get("priv_esc_threshold", 3))
    created = 0
    q = db.session.query(Event).order_by(Event.timestamp.desc()).limit(5000).all()
    
    failed_by_ip = defaultdict(list)
    failed_by_user = defaultdict(list)
    priv_events = defaultdict(int)
    unauth = defaultdict(int)
    susp = defaultdict(list)
    
    for e in q:
        et = e.event_type
        if et in ("Failed Login","SSH Failed Login"):
            failed_by_ip[e.source_ip].append(e)
            failed_by_user[e.username].append(e)
        if et in ("Privilege Escalation","Special Privileges Assigned","Root Login"):
            priv_events[e.source_ip] += 1
        if et in ("Unauthorized Access","Kerberos Failure"):
            unauth[e.source_ip] += 1
        if et in ("Suspicious Process","Malware Activity"):
            susp[e.source_ip].append(e)

    def add(alert_type, severity, title, desc, ip, user, count):
        nonlocal created
        if Alert.query.filter(Alert.alert_type==alert_type, Alert.source_ip==ip,
                              Alert.username==user, Alert.status!="Resolved").first():
            return
        a = Alert(alert_type=alert_type, severity=severity, title=title,
                  description=desc, source_ip=ip, username=user, count=count, status="New")
        db.session.add(a); created += 1

    for ip, evs in failed_by_ip.items():
        if len(evs) >= bf_thr:
            add("Brute Force Attack","Critical",f"Brute force from {ip}",
                f"{len(evs)} failed logins from {ip}.", ip, evs[-1].username, len(evs))
    for user, evs in failed_by_user.items():
        if len(evs) >= bf_thr and user not in ("-", None):
            add("Multiple Failed Logins","High",f"Repeated failures for {user}",
                f"{len(evs)} failed logins targeting '{user}'.", evs[-1].source_ip, user, len(evs))
    for ip, c in priv_events.items():
        if c >= pe_thr:
            add("Privilege Escalation","Critical",f"Privilege escalation near {ip}",
                f"{c} privilege-related events from {ip}.", ip, "-", c)
    for ip, c in unauth.items():
        if c >= 2:
            add("Unauthorized Access Attempt","High",f"Unauthorized access from {ip}",
                f"{c} unauthorized/kerberos failures from {ip}.", ip, "-", c)
    for ip, evs in susp.items():
        add("Suspicious Activity","Critical",f"Suspicious activity on {ip}",
            "; ".join(e.message[:60] for e in evs[:3]) or "Suspicious process/malware.",
            ip, evs[-1].username, len(evs))

    db.session.commit()
    try: audit_logger.record("DETECTION_RUN", f"created {created} alerts")
    except Exception: pass
    return created

def security_score():
    crit = Alert.query.filter_by(severity="Critical").count()
    high = Alert.query.filter_by(severity="High").count()
    med = Alert.query.filter_by(severity="Medium").count()
    open_inc = Incident_open_count()
    score = 100 - (crit*12) - (high*7) - (med*3) - (open_inc*5)
    return max(0, min(100, score))

def Incident_open_count():
    from models import Incident
    return Incident.query.filter(Incident.status.in_(("Open","Investigating"))).count()