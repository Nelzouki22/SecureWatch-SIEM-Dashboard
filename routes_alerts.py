from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required
from models import db, Alert
import alert_engine, audit_logger

bp = Blueprint("alerts", __name__)

@bp.route("/alerts")
@login_required
def list_alerts():
    sev = request.args.get("severity")
    status = request.args.get("status")
    q = Alert.query
    if sev: q = q.filter(Alert.severity == sev)
    if status: q = q.filter(Alert.status == status)
    alerts = q.order_by(Alert.created_at.desc()).all()
    return render_template("alerts.html", alerts=alerts,
        severities=["Low","Medium","High","Critical"],
        statuses=["New","Acknowledged","Resolved"])

@bp.route("/alerts/run-detection", methods=["POST"])
@login_required
def run_detection():
    created = alert_engine.run_detections()
    audit_logger.record("RUN_DETECTION", f"created {created} alerts")
    flash(f"Detection complete. {created} new alert(s) generated.", "success")
    return redirect(url_for("alerts.list_alerts"))

@bp.route("/alerts/<int:aid>/status", methods=["POST"])
@login_required
def set_status(aid):
    a = db.session.get(Alert, aid)
    if not a:
        flash("Alert not found.", "danger")
        return redirect(url_for("alerts.list_alerts"))
    a.status = request.form.get("status", "New")
    db.session.commit()
    audit_logger.record("UPDATE_ALERT", f"#{aid} -> {a.status}")
    flash("Alert updated.", "success")
    return redirect(url_for("alerts.list_alerts"))