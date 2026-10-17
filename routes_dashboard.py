from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from flask_login import login_required
from datetime import datetime
from sqlalchemy import func
from models import db, Event, Alert, Incident, Setting
import alert_engine, i18n

bp = Blueprint("dashboard", __name__)
SEV_ORDER = ["Information","Warning","Medium","High","Critical"]

@bp.route("/set_lang/<lang>")
def set_lang(lang):
    if lang in i18n.SUPPORTED: session["lang"] = lang
    s = Setting.query.filter_by(key="language").first()
    if s: s.value = lang; db.session.commit()
    return redirect(request.referrer or url_for("dashboard.index"))

@bp.route("/set_theme/<theme>")
@login_required
def set_theme(theme):
    theme = "dark" if theme == "dark" else "light"
    session["theme"] = theme
    s = Setting.query.filter_by(key="theme").first()
    if s: s.value = theme; db.session.commit()
    return redirect(request.referrer or url_for("dashboard.index"))

@bp.route("/dashboard")
@login_required
def index():
    total = Event.query.count()
    by_sev = {s:0 for s in SEV_ORDER}
    for sev, c in db.session.query(Event.severity, func.count()).group_by(Event.severity).all():
        by_sev[sev] = by_sev.get(sev, 0) + c
    failed = Event.query.filter(Event.event_type.like("%Failed%")).count()
    alerts = Alert.query.count()
    critical_alerts = Alert.query.filter_by(severity="Critical").count()
    open_inc = Incident.query.filter(Incident.status.in_(("Open","Investigating"))).count()
    score = alert_engine.security_score()
    
    days = (db.session.query(func.date(Event.timestamp).label("d"), func.count())
            .group_by("d").order_by("d").limit(14).all())
    events_per_day = {"labels":[str(d) for d,_ in days], "values":[c for _,c in days]}
    top_ips = db.session.query(Event.source_ip, func.count(Event.id)).filter(
        Event.source_ip.notin_(("-","localhost","127.0.0.1"))).group_by(Event.source_ip).order_by(
        func.count(Event.id).desc()).limit(6).all()
    top_users = db.session.query(Event.username, func.count(Event.id)).filter(
        Event.username.notin_(("-","system"))).group_by(Event.username).order_by(
        func.count(Event.id).desc()).limit(6).all()
    inc_status = dict(Incident.query.with_entities(Incident.status, func.count()).group_by(Incident.status).all())
    
    ctx = dict(
        total=total, by_sev=by_sev, failed=failed, alerts=alerts,
        critical_alerts=critical_alerts, open_inc=open_inc, score=score,
        events_per_day=events_per_day,
        top_ips={"labels":[i for i,_ in top_ips], "values":[c for _,c in top_ips]},
        top_users={"labels":[u for u,_ in top_users], "values":[c for _,c in top_users]},
        severity_dist={"labels":SEV_ORDER, "values":[by_sev[s] for s in SEV_ORDER]},
        inc_status={"labels":list(inc_status.keys()), "values":list(inc_status.values())},
        recent_events=Event.query.order_by(Event.timestamp.desc()).limit(8).all(),
        recent_alerts=Alert.query.order_by(Alert.created_at.desc()).limit(5).all()
    )
    return render_template("dashboard.html", **ctx)