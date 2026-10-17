from flask import Blueprint, render_template, request, send_file, redirect, url_for, flash
from flask_login import login_required
from io import BytesIO
import report_generator, audit_logger

bp = Blueprint("reports", __name__)

@bp.route("/reports")
@login_required
def index():
    return render_template("reports.html")

@bp.route("/reports/<period>/<fmt>")
@login_required
def generate(period, fmt):
    if period not in ("daily","weekly","monthly"):
        flash("Bad period.", "danger")
        return redirect(url_for("reports.index"))
    if fmt == "csv":
        data = report_generator.to_csv(period).encode("utf-8")
        name = f"securewatch_{period}.csv"
    else:
        data = report_generator.to_pdf_bytes(period)
        name = f"securewatch_{period}.pdf"
    audit_logger.record("EXPORT_REPORT", f"{period}/{fmt}")
    mimetype = "text/csv" if fmt == "csv" else "application/pdf"
    return send_file(BytesIO(data), as_attachment=True, download_name=name, mimetype=mimetype)