import logging, os
from datetime import datetime
from flask_login import current_user
from models import db, AuditLog

logger = logging.getLogger("securewatch.audit")

def configure_audit_logging(app):
    os.makedirs(app.config["LOG_DIR"], exist_ok=True)
    handler = logging.FileHandler(app.config["AUDIT_LOG_FILE"])
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        logger.addHandler(handler)

def record(action, detail="", user=None, ip=None):
    try:
        username = (user.username if user else 
                   (current_user.username if getattr(current_user, 'is_authenticated', False) else "anonymous"))
        entry = AuditLog(username=username, action=action, detail=detail, ip_address=ip or "-")
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error("audit db write failed: %s", e)
    logger.info("AUDIT user=%s action=%s detail=%s ip=%s",
                (user.username if user else getattr(current_user, 'username', 'anon')),
                action, detail, ip or "-")