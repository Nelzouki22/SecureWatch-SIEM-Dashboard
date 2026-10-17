import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(os.getcwd(), "database", "siem.db")
    )
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get("SESSION_TIMEOUT_MIN", 30)))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True
    WTF_CSRF_TIME_LIMIT = None
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = "200/minute"
    RATELIMIT_HEADERS_ENABLED = True
    LOG_DIR = os.path.join(os.getcwd(), "logs")
    REPORT_DIR = os.path.join(os.getcwd(), "reports")
    AUDIT_LOG_FILE = os.path.join(os.getcwd(), "logs", "audit.log")
    BRUTE_FORCE_THRESHOLD = int(os.environ.get("BRUTE_FORCE_THRESHOLD", 5))
    PRIV_ESC_THRESHOLD = int(os.environ.get("PRIV_ESC_THRESHOLD", 3))