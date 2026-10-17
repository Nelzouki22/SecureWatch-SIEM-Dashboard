"""
SecureWatch SIEM Dashboard - Main Application.

Flask application factory and route registration.
"""

import os
import json
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from database import db
from models import User, Event, Alert, Incident, AuditLog, Setting
import config as cfg_mod
import database
import siem_engine
import alert_engine
import incident_manager
import report_generator
import audit_logger
import i18n

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)


def create_app(test_config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(cfg_mod.Config)
    if test_config:
        app.config.update(test_config)

    root = os.path.dirname(os.path.abspath(__file__))
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(root, "database", "siem.db")
    app.config["LOG_DIR"] = os.path.join(root, "logs")
    app.config["REPORT_DIR"] = os.path.join(root, "reports")
    app.config["AUDIT_LOG_FILE"] = os.path.join(root, "logs", "audit.log")
    os.makedirs(app.config["LOG_DIR"], exist_ok=True)
    os.makedirs(app.config["REPORT_DIR"], exist_ok=True)

    database.init_db(app)
    csrf.init_app(app)
    limiter.init_app(app)
    audit_logger.configure_audit_logging(app)

    # ✅ Flask-Login setup (compatible with version 0.6.3)
    lm = LoginManager()
    lm.login_view = "auth.login"
    lm.session_protection = "strong"
    lm.init_app(app)

    @lm.user_loader
    def load_user(uid):
        """Load user by ID for Flask-Login."""
        return db.session.get(User, int(uid))

    @app.context_processor
    def inject_i18n():
        """Inject internationalization context into templates."""
        lang_setting = Setting.query.filter_by(key="language").first()
        lang = session.get("lang", lang_setting.value if lang_setting else "en")
        theme = session.get("theme", "light")
        return dict(
            t=lambda k, **kw: i18n.t(k, lang, **kw),
            lang=lang,
            rtl=i18n.is_rtl(lang),
            supported_langs=i18n.SUPPORTED,
            theme=theme,
            current_year=datetime.utcnow().year,
        )

    # Register blueprints
    from routes_dashboard import bp as dash_bp
    from routes_events import bp as ev_bp
    from routes_alerts import bp as al_bp
    from routes_incidents import bp as inc_bp
    from routes_reports import bp as rep_bp
    from routes_settings import bp as set_bp
    import auth

    for blueprint in (auth.bp, dash_bp, ev_bp, al_bp, inc_bp, rep_bp, set_bp):
        app.register_blueprint(blueprint)

    @app.route("/")
    def home():
        """Redirect to dashboard or login based on authentication."""
        if current_user.is_authenticated:
            return redirect(url_for("dashboard.index"))
        return redirect(url_for("auth.login"))

    @app.errorhandler(404)
    def not_found(e):
        """Handle 404 errors."""
        return render_template("error.html", code=404), 404

    @app.errorhandler(500)
    def internal_error(e):
        """Handle 500 errors."""
        return render_template("error.html", code=500), 500

    return app


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        try:
            incident_manager.seed_from_json(
                os.path.join(os.path.dirname(__file__), "incidents", "sample_incidents.json")
            )
            for f in (
                "windows_security_logs.json",
                "linux_logs.json",
                "firewall_logs.json",
                "active_directory_logs.json",
            ):
                p = os.path.join(os.path.dirname(__file__), "logs", f)
                if os.path.exists(p) and Event.query.count() < 50:
                    n, _ = siem_engine.ingest_file(p)
                    print(f"seeded {n} events from {f}")
            alert_engine.run_detections()
        except Exception as e:
            print("seed note:", e)

    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)