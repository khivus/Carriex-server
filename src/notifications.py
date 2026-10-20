"""Revocable, persistent credentials that can read only the owner's queue count."""
import hashlib
import secrets
import time

from flask import Blueprint, current_app, g, jsonify, request
from src.store import store

api = Blueprint("notifications", __name__)


def count_identity(authorization):
    if not authorization.startswith("Bearer "):
        return None
    token = authorization[7:]
    if len(token) != 43 or not token.isascii() or any(not (c.isalnum() or c in "_-") for c in token):
        return None
    digest = hashlib.sha256(token.encode("ascii")).digest()
    with store().connect() as db:
        row = db.execute("SELECT owner FROM notification_tokens WHERE token_hash=? AND expires_at>?",
                         (digest, int(time.time()))).fetchone()
    return row[0] if row else None


@api.post("/notifications/token")
def issue_token():
    ttl = int(current_app.config.get("NOTIFICATION_TOKEN_TTL", 7 * 86400))
    if not 1 <= ttl <= 30 * 86400:
        return jsonify(error="Invalid notification token lifetime"), 503
    token = secrets.token_urlsafe(32)
    with store().connect() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM notification_tokens WHERE expires_at<=?", (int(time.time()),))
        own = db.execute("SELECT 1 FROM notification_tokens WHERE owner=?", (g.user_id,)).fetchone()
        if not own and db.execute("SELECT count(*) FROM notification_tokens").fetchone()[0] >= current_app.config.get("NOTIFICATION_TOKEN_LIMIT", 4096):
            return jsonify(error="Notification credential capacity reached"), 429
        db.execute("""INSERT INTO notification_tokens VALUES (?,?,?) ON CONFLICT(owner) DO UPDATE
            SET token_hash=excluded.token_hash,expires_at=excluded.expires_at""",
                   (g.user_id, hashlib.sha256(token.encode("ascii")).digest(), int(time.time()) + ttl))
    return jsonify(token=token, expires_in=ttl, user_id=g.user_id, scope="notifications.count"), 200


@api.delete("/notifications/token")
def revoke_token():
    with store().connect() as db:
        db.execute("DELETE FROM notification_tokens WHERE owner=?", (g.user_id,))
    return jsonify(status="ok"), 200


@api.get("/messages/<user_id>/count")
def pending_count(user_id):
    from src.groups import pending_count as group_count
    result = store().pending_count(user_id)
    count, revision = group_count(user_id)
    result["pending_count"] += count
    result["revision"] = max(result["revision"], revision)
    return jsonify(result), 200


def register_notifications(app):
    with app.app_context(), store().connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS notification_tokens
            (owner TEXT PRIMARY KEY,token_hash BLOB NOT NULL UNIQUE,expires_at INTEGER NOT NULL)""")
    app.register_blueprint(api)

    @app.after_request
    def private_counts(response):
        if request.endpoint and request.endpoint.startswith("notifications."):
            response.headers["Cache-Control"] = "no-store"
        return response
