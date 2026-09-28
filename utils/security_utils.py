from __future__ import annotations

import os
from functools import wraps
from flask import jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash


def is_logged_in() -> bool:
    return bool(session.get("logged_in"))


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if is_logged_in():
            return view_func(*args, **kwargs)
        if request.path.startswith("/api/") or request.is_json:
            return jsonify({"error": "Authentication required."}), 401
        return redirect(url_for("login"))
    return wrapper


def verify_admin_reset_secret(candidate: str) -> bool:
    stored_hash = os.environ.get("WAQQAS_RESET_SECRET_HASH", "")
    if not stored_hash:
        return False
    return check_password_hash(stored_hash, candidate or "")