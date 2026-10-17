import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.engine import Engine
from sqlalchemy import event

db = SQLAlchemy()

def init_db(app):
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    db.init_app(app)
    _ensure_dirs(app)
    with app.app_context():
        from models import User, Event, Alert, Incident, AuditLog, Setting
        db.create_all()
        seed_defaults(app)

def _ensure_dirs(app):
    for d in (app.config["LOG_DIR"], app.config["REPORT_DIR"]):
        os.makedirs(d, exist_ok=True)
    uri = app.config["SQLALCHEMY_DATABASE_URI"]
    if uri.startswith("sqlite:///"):
        path = uri.replace("sqlite:///", "")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    except Exception:
        pass

def seed_defaults(app):
    from models import User, Setting
    from werkzeug.security import generate_password_hash
    with app.app_context():
        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                email="admin@securewatch.local",
                password_hash=generate_password_hash("Admin@1234"),
                role="admin",
            )
            db.session.add(admin)
        for key, value in {
            "theme": "light", "language": "en",
            "brute_force_threshold": str(app.config["BRUTE_FORCE_THRESHOLD"]),
            "priv_esc_threshold": str(app.config["PRIV_ESC_THRESHOLD"]),
        }.items():
            if not Setting.query.filter_by(key=key).first():
                db.session.add(Setting(key=key, value=value))
        db.session.commit()