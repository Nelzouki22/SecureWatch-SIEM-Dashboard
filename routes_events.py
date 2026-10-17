import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, abort
from flask_login import login_required
from werkzeug.utils import secure_filename
from datetime import datetime
from models import db, Event
import siem_engine, audit_logger

bp = Blueprint("events", __name__)
SEVERITIES = ["Information","Warning","Medium","High","Critical"]

@bp.route("/events")
@login_required
def list_events():
    q = Event.query
    username = request.args.get("username")
    event_id = request.args.get("event_id")
    severity = request.args.get("severity")
    source_ip = request.args.get("source_ip")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    
    if username: q = q.filter(Event.username.ilike(f"%{username}%"))
    if event_id and str(event_id).isdigit(): q = q.filter(Event.event_id == int(event_id))
    if severity: q = q.filter(Event.severity == severity)
    if source_ip: q = q.filter(Event.source_ip.ilike(f"%{source_ip}%"))
    if date_from:
        try: q = q.filter(Event.timestamp >= datetime.strptime(date_from, "%Y-%m-%d"))
        except Exception: pass
    if date_to:
        try: q = q.filter(Event.timestamp <= datetime.strptime(date_to + " 23:59:59", "%Y-%m-%d %H:%M:%S"))
        except Exception: pass
    
    page = request.args.get("page", type=int, default=1)
    pagination = q.order_by(Event.timestamp.desc()).paginate(page=page, per_page=25, error_out=False)
    return render_template("events.html", pagination=pagination, severities=SEVERITIES,
        filters=dict(username=username, event_id=event_id, severity=severity,
                     source_ip=source_ip, date_from=date_from, date_to=date_to))

@bp.route("/ingest", methods=["GET","POST"])
@login_required
def ingest():
    if request.method == "POST":
        f = request.files.get("logfile")
        src = request.form.get("source", "auto")
        if not f or not f.filename:
            flash("Please choose a log file.", "warning")
            return redirect(url_for("events.ingest"))
        fn = secure_filename(f.filename)
        path = os.path.join(current_app.config["LOG_DIR"], fn)
        f.save(path)
        n, fmt = siem_engine.ingest_file(path)
        audit_logger.record("INGEST_LOG", f"{fn} ({fmt}) -> {n} events")
        flash(f"Imported {n} events from {fn} (format: {fmt}).", "success")
        return redirect(url_for("events.list_events"))
    
    samples = [x for x in ("windows_security_logs.json","linux_logs.json","firewall_logs.json",
                           "active_directory_logs.json","sample_logs.json")
               if os.path.exists(os.path.join(current_app.config["LOG_DIR"], x))]
    return render_template("ingest.html", samples=samples)

@bp.route("/ingest/sample/<path:name>")
@login_required
def ingest_sample(name):
    path = os.path.join(current_app.config["LOG_DIR"], os.path.basename(name))
    if not os.path.exists(path): abort(404)
    n, fmt = siem_engine.ingest_file(path)
    audit_logger.record("INGEST_SAMPLE", f"{name} -> {n}")
    flash(f"Loaded {n} sample events from {name}.", "success")
    return redirect(url_for("events.list_events"))