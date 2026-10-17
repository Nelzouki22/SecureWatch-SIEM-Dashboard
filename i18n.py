"""
Internationalization support for SecureWatch SIEM Dashboard.

Loads translation files and provides translation function.
"""

import json
import os

TRANSLATIONS_DIR = os.path.join(os.path.dirname(__file__), "translations")
_cache = {}
SUPPORTED = ("en", "ar")
RTL = {"ar"}


def load(lang):
    """Load translation file for the given language."""
    if lang not in _cache:
        p = os.path.join(TRANSLATIONS_DIR, f"{lang}.json")
        try:
            _cache[lang] = json.load(open(p, encoding="utf-8"))
        except Exception:
            _cache[lang] = {}
    return _cache[lang]


def t(key, lang="en", **kw):
    """
    Translate a key with support for nested keys (e.g., 'nav.dashboard').
    
    Args:
        key: Translation key (can be nested like 'nav.dashboard')
        lang: Language code ('en' or 'ar')
        **kw: Format parameters
    
    Returns:
        Translated string or the key itself if not found
    """
    d = load(lang)
    base = load("en")
    
    # ✅ Support nested keys: "nav.dashboard" -> d["nav"]["dashboard"]
    val = _get_nested(d, key) or _get_nested(base, key) or key
    
    try:
        return val.format(**kw)
    except Exception:
        return val


def _get_nested(d, key):
    """
    Get value from nested dictionary using dot notation.
    
    Example: _get_nested({"nav": {"dashboard": "Dashboard"}}, "nav.dashboard")
    Returns: "Dashboard"
    """
    keys = key.split(".")
    val = d
    for k in keys:
        if isinstance(val, dict) and k in val:
            val = val[k]
        else:
            return None
    return val if isinstance(val, str) else None


def is_rtl(lang):
    """Check if language is right-to-left."""
    return lang in RTL