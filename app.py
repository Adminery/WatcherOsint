#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WatcherOsint — API entrypoint (v1.1, hardened)
"""
import os
import secrets
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

from Number import bp as phone_bp
from Email import bp as email_bp
from Username import bp as username_bp
from auth import bp as auth_bp          # ← lowercase (Linux case-sensitive)

VERSION = "1.1.0"
IS_DEV = os.environ.get("ENV", "production") == "development"

# Server-side keys
NUMVERIFY_KEY = os.environ.get("NUMVERIFY_API_KEY", "")
HUNTER_KEY = os.environ.get("HUNTER_API_KEY", "")

# --- CORS origins ---
_default_origins = "http://127.0.0.1:5500,http://localhost:5500"
ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get("ALLOWED_ORIGINS", _default_origins).split(",")
    if o.strip()
]

# --- Flask app ---
app = Flask(__name__)

# Trust X-Forwarded-* from Render/Nginx — CRITICAL for Secure cookies
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# --- SECRET_KEY ---
secret = os.environ.get("SECRET_KEY")
if not secret:
    if IS_DEV:
        secret = secrets.token_hex(32)
        print("WARNING: dev mode — using random SECRET_KEY (sessions reset on restart)")
    else:
        raise RuntimeError("SECRET_KEY environment variable is required in production")

app.config.update(
    SECRET_KEY=secret,
    SESSION_COOKIE_NAME="wo_sid",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=not IS_DEV,          # True in prod (needs HTTPS)
    SESSION_COOKIE_SAMESITE="Lax" if IS_DEV else "None",  # None for cross-site cookie
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 14,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,        # 2 MB
    JSON_SORT_KEYS=False,
)

# --- CORS ---
# /api/* covers auth (mounted at /api/auth) and all other blueprints
CORS(
    app,
    resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=True,
    allow_headers=["Content-Type", "X-CSRF-Token"],
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)

# --- Blueprints ---
app.register_blueprint(phone_bp)
app.register_blueprint(email_bp)
app.register_blueprint(username_bp)
app.register_blueprint(auth_bp)

# --- Security headers ---
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cache-Control"] = "no-store"
    if not IS_DEV:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # NOTE: no CSP here — HTML is served by GitHub Pages, not by this API.
    # Set CSP in the <meta> tag or via GitHub Pages hosting if needed.
    return resp

# --- Health ---
@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": VERSION})

# --- Errors ---
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "not_found"}), 404
    return jsonify({"success": False, "error": "not_found"}), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({"success": False, "error": "payload_too_large"}), 413

@app.errorhandler(500)
def server_error(e):
    return jsonify({"success": False, "error": "server_error"}), 500

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=debug)
