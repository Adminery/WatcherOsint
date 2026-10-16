#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WatcherOsint - Auth blueprint (v1.1 - hardened)
Handles: signup, login, logout, session/me, CSRF, forgot/reset password,
Google OAuth, GitHub OAuth.
"""
import os
import time
import hmac
import html
import secrets
import hashlib
import sqlite3
import threading
from functools import wraps
from datetime import timedelta

from flask import Blueprint, request, session, jsonify, redirect, current_app
from werkzeug.security import generate_password_hash, check_password_hash

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# ------------------------------------------------------------------
# Rate limiter (per-IP sliding window, thread-safe)
# ------------------------------------------------------------------
_rate = {}
_rate_lock = threading.Lock()
RATE_LIMITS = {
    "login":   (5, 60),
    "signup":  (3, 300),
    "reset":   (3, 300),
    "verify":  (10, 300),
    "csrf":    (30, 60),
}

def _rate_limit(route):
    key = f"{request.remote_addr}:{route}"
    limit, window = RATE_LIMITS.get(route, (10, 60))
    now = time.time()
    with _rate_lock:
        q = [t for t in _rate.get(key, []) if now - t < window]
        if len(q) >= limit:
            _rate[key] = q
            return "Too many attempts. Please wait and try again."
        q.append(now)
        _rate[key] = q
    return None

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _s(v, maxlen=200):
    """Escape + strip control chars for safe output."""
    if v is None:
        return ""
    v = str(v)
    v = "".join(ch for ch in v if ord(ch) >= 32)
    return html.escape(v[:maxlen])

def _valid_email(e):
    e = (e or "").strip().lower()
    if len(e) > 190 or "@" not in e or "." not in e.split("@")[-1]:
        return None
    if any(ch.isspace() for ch in e) or "<>" in e or ".." in e:
        return None
    local, _, domain = e.partition("@")
    if not local or not domain:
        return None
    return e

def _valid_username(u):
    u = (u or "").strip()
    if not (3 <= len(u) <= 32):
        return None
    if not all(ch.isalnum() or ch in "._-" for ch in u):
        return None
    if u.startswith((".", "_", "-")) or u.endswith((".", "_", "-")):
        return None
    return u

def _valid_password(p):
    if not p or len(p) < 8 or len(p) > 128:
        return "Password must be 8-128 characters."
    return None

# ------------------------------------------------------------------
# Database (SQLite; on Render mount a Persistent Disk at /data)
# ------------------------------------------------------------------
_default_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "watos.db")
DB_PATH = os.environ.get("WATOS_DB", _default_db)

def _conn():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c

def _init_db():
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            username TEXT,
            oauth_provider TEXT,
            oauth_id TEXT,
            created REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reset_codes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            expires REAL NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_reset_email ON reset_codes(email);
        CREATE TABLE IF NOT EXISTS sessions(
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires REAL NOT NULL
        );
        """)

_init_db()

def _get_user(email=None, uid=None):
    with _conn() as c:
        if uid is not None:
            row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        else:
            row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        return dict(row) if row else None

# ------------------------------------------------------------------
# CSRF
# ------------------------------------------------------------------
def _set_csrf():
    token = secrets.token_urlsafe(32)
    session["csrf"] = token
    return token

def require_csrf(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            got = request.headers.get("X-CSRF-Token") or ""
            if not session.get("csrf") or not hmac.compare_digest(session["csrf"], got):
                return jsonify({
                    "success": False,
                    "error": "invalid_csrf",
                    "message": "Session expired. Refresh the page."
                }), 403
        return f(*args, **kwargs)
    return wrapper

# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@bp.route("/csrf", methods=["GET"])
def csrf():
    rl = _rate_limit("csrf")
    if rl:
        return jsonify({"success": False, "message": rl}), 429
    return jsonify({"success": True, "token": _set_csrf()})

@bp.route("/me", methods=["GET"])
def me():
    uid = session.get("uid")
    if not uid:
        return jsonify({"success": True, "authenticated": False})
    u = _get_user(uid=uid)
    if not u:
        session.clear()
        return jsonify({"success": True, "authenticated": False})
    return jsonify({
        "success": True,
        "authenticated": True,
        "user": {
            "email": _s(u["email"], 190),
            "username": _s(u["username"] or "", 32),
            "oauth": _s(u["oauth_provider"] or "", 20) or None
        }
    })

@bp.route("/signup", methods=["POST"])
@require_csrf
def signup():
    rl = _rate_limit("signup")
    if rl:
        return jsonify({"success": False, "message": rl}), 429

    data = request.get_json(silent=True) or {}
    email = _valid_email(data.get("email"))
    username = _valid_username(data.get("username"))
    pw_err = _valid_password(data.get("password"))

    if not email:
        return jsonify({"success": False, "message": "Invalid email address."}), 400
    if not username:
        return jsonify({"success": False, "message": "Username must be 3-32 chars (letters, digits, . _ -)."}), 400
    if pw_err:
        return jsonify({"success": False, "message": pw_err}), 400

    if _get_user(email=email):
        return jsonify({"success": False, "message": "An account with this email already exists."}), 409

    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO users(email, password_hash, username, created) VALUES(?,?,?,?)",
                (email, generate_password_hash(data["password"]), username, time.time())
            )
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "An account with this email already exists."}), 409

    u = _get_user(email=email)
    session.clear()
    session.permanent = True
    session["uid"] = u["id"]
    _set_csrf()
    return jsonify({
        "success": True,
        "user": {"email": _s(u["email"]), "username": _s(u["username"]), "oauth": None}
    })

@bp.route("/login", methods=["POST"])
@require_csrf
def login():
    rl = _rate_limit("login")
    if rl:
        return jsonify({"success": False, "message": rl}), 429

    data = request.get_json(silent=True) or {}
    email = _valid_email(data.get("email"))
    password = data.get("password") or ""
    keep = bool(data.get("remember"))

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400

    u = _get_user(email=email)
    # Timing-safe: always hash-compare even when user missing/oauth-only
    stored = (u or {}).get("password_hash") or "!"
    if stored == "!":
        # dummy compare to keep timing constant
        check_password_hash(generate_password_hash("dummy"), password)
        return jsonify({"success": False, "message": "Invalid email or password."}), 401

    if (u.get("oauth_provider")):
        return jsonify({"success": False, "message": "Invalid email or password."}), 401

    if not check_password_hash(stored, password):
        return jsonify({"success": False, "message": "Invalid email or password."}), 401

    session.clear()
    session.permanent = True
    if keep:
        current_app.permanent_session_lifetime = timedelta(days=14)
    else:
        current_app.permanent_session_lifetime = timedelta(days=1)
    session["uid"] = u["id"]
    _set_csrf()
    return jsonify({
        "success": True,
        "user": {"email": _s(u["email"]), "username": _s(u["username"] or ""), "oauth": None}
    })

@bp.route("/logout", methods=["POST"])
@require_csrf
def logout():
    session.clear()
    return jsonify({"success": True})

# ------------------------------------------------------------------
# Forgot / reset password
# ------------------------------------------------------------------
def _send_reset_email(to_email, code):
    smtp = os.environ.get("SMTP_HOST")
    if not smtp:
        print(f"[RESET] code for {to_email}: {code}")
        return True
    import smtplib
    from email.mime.text import MIMEText
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
        user = os.environ.get("SMTP_USER")
        pw = os.environ.get("SMTP_PASS")
        msg = MIMEText(f"Your WatcherOsint password reset code is: {code}\nIt expires in 10 minutes.")
        msg["Subject"] = "WatcherOsint password reset"
        msg["From"] = user or smtp
        msg["To"] = to_email
        s = smtplib.SMTP(smtp, port, timeout=15)
        s.starttls()
        if user:
            s.login(user, pw)
        s.send_message(msg)
        s.quit()
        return True
    except Exception as e:
        print(f"[RESET] email failed for {to_email}: {e}")
        return False

@bp.route("/forgot", methods=["POST"])
@require_csrf
def forgot():
    rl = _rate_limit("reset")
    if rl:
        return jsonify({"success": False, "message": rl}), 429

    data = request.get_json(silent=True) or {}
    email = _valid_email(data.get("email"))
    if not email:
        return jsonify({"success": False, "message": "Invalid email address."}), 400

    u = _get_user(email=email)
    if u and not u.get("oauth_provider"):
        code = f"{secrets.randbelow(1000000):06d}"
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        expires = time.time() + 600
        with _conn() as c:
            c.execute(
                "INSERT INTO reset_codes(email, code_hash, expires, used) VALUES(?,?,?,0)",
                (email, code_hash, expires)
            )
        _send_reset_email(email, code)

    # Always same response (no user enumeration)
    return jsonify({"success": True, "message": "If that email exists, a reset code has been sent."})

@bp.route("/reset", methods=["POST"])
@require_csrf
def reset():
    rl = _rate_limit("verify")
    if rl:
        return jsonify({"success": False, "message": rl}), 429

    data = request.get_json(silent=True) or {}
    email = _valid_email(data.get("email"))
    code = (data.get("code") or "").strip()
    new_pass = data.get("password") or ""

    if not email or not code:
        return jsonify({"success": False, "message": "Email and code are required."}), 400
    pw_err = _valid_password(new_pass)
    if pw_err:
        return jsonify({"success": False, "message": pw_err}), 400

    code_hash = hashlib.sha256(code.encode()).hexdigest()
    with _conn() as c:
        row = c.execute(
            """SELECT id, expires, used FROM reset_codes
               WHERE email=? AND code_hash=? ORDER BY id DESC LIMIT 1""",
            (email, code_hash)
        ).fetchone()
        if not row or row["used"] or row["expires"] < time.time():
            return jsonify({"success": False, "message": "Invalid or expired code."}), 400
        c.execute(
            "UPDATE users SET password_hash=? WHERE email=?",
            (generate_password_hash(new_pass), email)
        )
        c.execute("UPDATE reset_codes SET used=1 WHERE id=?", (row["id"],))
    session.clear()
    return jsonify({"success": True, "message": "Password updated. You can now log in."})

# ------------------------------------------------------------------
# OAuth (server-side; secrets never reach the browser)
# ------------------------------------------------------------------
def _oauth_redirect_uri(provider):
    # Trust X-Forwarded-Proto (set by Render/nginx) via ProxyFix in app.py
    base = request.url_root.rstrip("/")
    return f"{base}/api/auth/{provider}/callback"

@bp.route("/google/login")
def google_login():
    cid = os.environ.get("GOOGLE_CLIENT_ID")
    if not cid:
        return jsonify({"success": False, "message": "Google OAuth not configured."}), 503
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    redir = _oauth_redirect_uri("google")
    uri = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={cid}"
        f"&redirect_uri={redir}"
        "&response_type=code"
        "&scope=openid%20email%20profile"
        f"&state={state}"
    )
    return redirect(uri)

@bp.route("/google/callback")
def google_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    saved = session.pop("oauth_state", "")
    if not code or not state or not hmac.compare_digest(saved, state):
        return jsonify({"success": False, "message": "OAuth state mismatch."}), 400

    import requests
    cid = os.environ.get("GOOGLE_CLIENT_ID")
    csec = os.environ.get("GOOGLE_CLIENT_SECRET")
    redir = _oauth_redirect_uri("google")

    tok = requests.post("https://oauth2.googleapis.com/token", data={
        "code": code, "client_id": cid, "client_secret": csec,
        "redirect_uri": redir, "grant_type": "authorization_code"
    }, timeout=10).json()
    at = tok.get("access_token")
    if not at:
        return jsonify({"success": False, "message": "OAuth failed."}), 400

    prof = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {at}"}, timeout=10
    ).json()
    email = _valid_email(prof.get("email"))
    if not email:
        return jsonify({"success": False, "message": "Could not read profile email."}), 400

    u = _get_user(email=email)
    if not u:
        try:
            with _conn() as c:
                c.execute(
                    "INSERT INTO users(email, password_hash, username, oauth_provider, oauth_id, created) "
                    "VALUES(?,?,?,?,?,?)",
                    (email, "!", (prof.get("name") or email.split("@")[0])[:32],
                     "google", str(prof.get("id") or ""), time.time())
                )
        except sqlite3.IntegrityError:
            pass
        u = _get_user(email=email)

    session.clear()
    session.permanent = True
    session["uid"] = u["id"]
    _set_csrf()
    return redirect("/")

@bp.route("/github/login")
def github_login():
    cid = os.environ.get("GITHUB_CLIENT_ID")
    if not cid:
        return jsonify({"success": False, "message": "GitHub OAuth not configured."}), 503
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    redir = _oauth_redirect_uri("github")
    return redirect(
        "https://github.com/login/oauth/authorize"
        f"?client_id={cid}&state={state}&scope=user:email&redirect_uri={redir}"
    )

@bp.route("/github/callback")
def github_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    saved = session.pop("oauth_state", "")
    if not code or not state or not hmac.compare_digest(saved, state):
        return jsonify({"success": False, "message": "OAuth state mismatch."}), 400

    import requests
    cid = os.environ.get("GITHUB_CLIENT_ID")
    csec = os.environ.get("GITHUB_CLIENT_SECRET")

    tok = requests.post(
        "https://github.com/login/oauth/access_token",
        data={"client_id": cid, "client_secret": csec, "code": code},
        headers={"Accept": "application/json"}, timeout=10
    ).json()
    at = tok.get("access_token")
    if not at:
        return jsonify({"success": False, "message": "OAuth failed."}), 400

    headers = {"Authorization": f"token {at}", "Accept": "application/vnd.github+json"}
    prof = requests.get("https://api.github.com/user", headers=headers, timeout=10).json()
    emails = requests.get("https://api.github.com/user/emails", headers=headers, timeout=10).json()

    email = None
    if isinstance(emails, list):
        email = next((e["email"] for e in emails if e.get("primary") and e.get("verified")), None)
    email = _valid_email(email or prof.get("email"))
    if not email:
        return jsonify({"success": False, "message": "No verified primary email on GitHub."}), 400

    u = _get_user(email=email)
    if not u:
        try:
            with _conn() as c:
                c.execute(
                    "INSERT INTO users(email, password_hash, username, oauth_provider, oauth_id, created) "
                    "VALUES(?,?,?,?,?,?)",
                    (email, "!", (prof.get("login") or email.split("@")[0])[:32],
                     "github", str(prof.get("id") or ""), time.time())
                )
        except sqlite3.IntegrityError:
            pass
        u = _get_user(email=email)

    session.clear()
    session.permanent = True
    session["uid"] = u["id"]
    _set_csrf()
    return redirect("/")
