import json, csv, os, re
from datetime import datetime
from models import db, Event

WINDOWS_MAP = {4624:"Login Success",4625:"Failed Login",4720:"User Created",
               4726:"User Deleted",4672:"Special Privileges Assigned",
               4688:"Suspicious Process",4768:"Kerberos Failure",
               4771:"Account Lockout",5156:"Firewall Allow",5157:"Firewall Block",
               4634:"Logout",4648:"Explicit Credential Logon"}
SEV_BY_TYPE = {"Failed Login":"Warning","Brute Force Attempt":"High",
               "Privilege Escalation":"Critical","Suspicious Process":"Critical",
               "Firewall Block":"Medium","Kerberos Failure":"High",
               "Unauthorized Access":"High","Login Success":"Information"}

def _norm_sev(s):
    s = (s or "").strip().title()
    return s if s in ("Information","Warning","Medium","High","Critical") else "Information"

def _parse_ts(t):
    if isinstance(t, datetime): return t
    for fmt in ("%Y-%m-%dT%H:%M:%S","%Y-%m-%d %H:%M:%S"):
        try: return datetime.strptime(str(t)[:19], fmt)
        except Exception: pass
    return datetime.utcnow()

def infer_event_type(event_id, raw_type=None):
    if raw_type: return raw_type
    try: return WINDOWS_MAP.get(int(event_id), "Unknown")
    except Exception: return raw_type or "Unknown"

def normalize(record, source="json"):
    etype = record.get("event_type") or infer_event_type(record.get("event_id"))
    sev = _norm_sev(record.get("severity") or SEV_BY_TYPE.get(etype, "Information"))
    return dict(
        event_id=int(record.get("event_id") or 0),
        timestamp=_parse_ts(record.get("timestamp")),
        severity=sev, event_type=etype,
        username=str(record.get("username") or "-"),
        source_ip=str(record.get("source_ip") or "-"),
        message=str(record.get("message") or ""),
        raw=json.dumps({k:str(v) for k,v in record.items()}),
        log_source=source,
    )

def ingest_records(records, source="json", commit=True):
    count = 0
    for r in records:
        db.session.add(Event(**normalize(r, source)))
        count += 1
    if commit: db.session.commit()
    return count

def load_json(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else [data]

def load_csv(path):
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            out.append(row)
    return out

def detect_format(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".csv": return "csv"
    if ext == ".json":
        data = load_json(path)
        first = data[0] if data else {}
        keys = set(first.keys())
        if {"Message","EventID","TimeCreated"} <= keys: return "windows"
        if {"host","service","msg","pid"} & keys: return "linux"
        if {"action","dst","proto","src"} & keys: return "firewall"
        return "json"
    return "json"

def parse_windows_evtx_like(path):
    recs = []
    for ev in load_json(path):
        eid = int(ev.get("EventID", 0))
        msg = ev.get("Message", "")
        m = re.search(r"Account Name:\s*([A-Za-z0-9_\-\.]+)", msg)
        u = m.group(1) if m else ev.get("AccountName", "-")
        mi = re.search(r"Source Network Address:\s*([0-9\.a-fA-F:]+)", msg)
        ip = mi.group(1) if mi else ev.get("IpAddress", "-")
        recs.append(dict(event_id=eid, timestamp=ev.get("TimeCreated"),
                         event_type=infer_event_type(eid), username=u, source_ip=ip,
                         message=msg[:500]))
    return recs

def ingest_file(path):
    fmt = detect_format(path)
    if fmt == "windows":
        recs = parse_windows_evtx_like(path); src = "windows"
    elif fmt == "csv":
        recs = load_csv(path); src = "csv"
    else:
        recs = load_json(path); src = fmt
    return ingest_records(recs, src), fmt