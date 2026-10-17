from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_required, current_user
from models import db, Setting, AuditLog
import audit_logger

bp = Blueprint("settings", __name__)

@bp.route("/settings", methods=["GET","POST"])
@login_required
def index():
    settings = {s.key: s.value for s in Setting.query.all()}
    if request.method == "POST":
        for k, v in (("theme", request.form.get("theme")),
                     ("language", request.form.get("language")),
                     ("brute_force_threshold", request.form.get("brute_force_threshold")),
                     ("priv_esc_threshold", request.form.get("priv_esc_threshold"))):
            if v is None: continue
            s = Setting.query.filter_by(key=k).first() or Setting(key=k)
            s.value = v
            db.session.add(s)
        db.session.commit()
        if request.form.get("theme"): session["theme"] = request.form.get("theme")
        if request.form.get("language"): session["lang"] = request.form.get("language")
        audit_logger.record("UPDATE_SETTINGS", "updated user preferences")
        flash("Settings saved.", "success")
        return redirect(url_for("settings.index"))
    return render_template("settings.html", settings=settings)

@bp.route("/audit")
@login_required
def audit_logs():
    page = request.args.get("page", type=int, default=1)
    action = request.args.get("action")
    q = AuditLog.query
    if action: q = q.filter(AuditLog.action == action)
    pagination = q.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=30, error_out=False)
    actions = [r[0] for r in db.session.query(AuditLog.action).distinct().all()]
    return render_template("audit_logs.html", pagination=pagination, actions=actions, action=action)