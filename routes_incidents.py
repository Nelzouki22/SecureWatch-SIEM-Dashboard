from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required
from models import db, Incident
import incident_manager, audit_logger

bp = Blueprint("incidents", __name__)

@bp.route("/incidents")
@login_required
def list_incidents():
    status = request.args.get("status")
    sev = request.args.get("severity")
    q = Incident.query
    if status: q = q.filter(Incident.status == status)
    if sev: q = q.filter(Incident.severity == sev)
    incidents = q.order_by(Incident.created_at.desc()).all()
    return render_template("incidents.html", incidents=incidents,
        statuses=["Open","Investigating","Resolved","Closed"],
        severities=["Low","Medium","High","Critical"])

@bp.route("/incidents/new", methods=["GET","POST"])
@login_required
def new_incident():
    if request.method == "POST":
        inc = incident_manager.create(
            request.form.get("title", "Untitled"),
            request.form.get("severity", "Medium"),
            request.form.get("assigned_to", ""),
            request.form.get("description", ""),
            request.form.get("notes", "")
        )
        flash(f"Incident {inc.incident_id} created.", "success")
        return redirect(url_for("incidents.list_incidents"))
    return render_template("incident_form.html", incident=None,
        severities=["Low","Medium","High","Critical"])

@bp.route("/incidents/<int:iid>", methods=["GET","POST"])
@login_required
def view_incident(iid):
    inc = db.session.get(Incident, iid)
    if not inc:
        flash("Not found.", "danger")
        return redirect(url_for("incidents.list_incidents"))
    if request.method == "POST":
        action = request.form.get("action")
        if action == "status":
            incident_manager.update_status(iid, request.form.get("status"), request.form.get("note", ""))
        elif action == "note":
            incident_manager.add_note(iid, request.form.get("note", ""))
        flash("Incident updated.", "success")
        return redirect(url_for("incidents.view_incident", iid=iid))
    return render_template("incident_detail.html", incident=inc,
        statuses=["Open","Investigating","Resolved","Closed"])

@bp.route("/incidents/seed", methods=["POST"])
@login_required
def seed():
    made = incident_manager.seed_from_json("incidents/sample_incidents.json")
    flash(f"Seeded {made} sample incidents.", "info")
    return redirect(url_for("incidents.list_incidents"))