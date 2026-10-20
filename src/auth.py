"""Device proof of possession and bounded, process-local authentication state.

Only public keys and SHA-256 hashes of bearer tokens are kept by the server.
Private signing keys never leave the client. TLS is required outside development.
"""
import base64
import hashlib
import re
import secrets
import time
from threading import Lock

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Blueprint, current_app, g, jsonify, request


api = Blueprint("auth", __name__)
ID_PATTERN = re.compile(r"[0-9a-f]{64}")


def valid_user_id(value):
    return isinstance(value, str) and ID_PATTERN.fullmatch(value) is not None


def decode_base64(value, maximum):
    if not isinstance(value, str) or not 0 < len(value) <= maximum:
        raise ValueError("invalid encoding")
    return base64.b64decode(value, validate=True)


def proof_bytes(user_id, challenge, audience):
    return f"Carriex device authentication v1\n{audience}\n{user_id}\n{challenge}".encode("utf-8")


class AuthStore:
    def __init__(self, session_ttl=3600, challenge_ttl=60):
        self.lock = Lock()
        self.devices = {}
        self.challenges = {}
        self.sessions = {}
        self.session_ttl = session_ttl
        self.challenge_ttl = challenge_ttl
        self.capacity = 10000

    def prune(self):
        now = time.monotonic()
        for records in (self.challenges, self.sessions):
            for key in [key for key, value in records.items() if value[-1] <= now]:
                del records[key]

    def session(self, authorization):
        if not authorization.startswith("Bearer "):
            return None
        token = authorization[7:]
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        with self.lock:
            key = hashlib.sha256(token.encode("ascii")).digest()
            value = self.sessions.get(key)
            if value is not None and value[1] > time.monotonic():
                return value
            self.sessions.pop(key, None)
        return None


def store():
    return current_app.extensions["device_auth"]


@api.post("/auth/challenge")
def challenge():
    data = request.get_json(silent=True)
    try:
        if not isinstance(data, dict):
            raise ValueError("invalid JSON")
        encoded = decode_base64(data.get("public_key"), 256)
        key = serialization.load_der_public_key(encoded)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("P-256 key required")
        canonical = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if canonical != encoded:
            raise ValueError("canonical SPKI required")
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return jsonify(error="A base64 DER/SPKI P-256 public key is required"), 400
    user_id = hashlib.sha256(canonical).hexdigest()
    # Production uses an operator-configured origin, never an untrusted Host
    # header. This prevents another server relaying a device's proof here.
    audience = current_app.config.get("AUTH_ORIGIN") or request.host_url.rstrip("/")
    auth = store()
    with auth.lock:
        auth.prune()
        if len(auth.challenges) >= auth.capacity:
            return jsonify(error="Too many pending challenges; retry later"), 429
        nonce = secrets.token_urlsafe(32)
        auth.challenges[nonce] = (user_id, key, audience, time.monotonic() + auth.challenge_ttl)
    return jsonify(challenge=nonce, user_id=user_id, audience=audience, expires_in=auth.challenge_ttl)


@api.post("/auth/verify")
def verify():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("challenge"), str):
        return jsonify(error="Invalid authentication proof"), 400
    nonce = data["challenge"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", nonce):
        return jsonify(error="Invalid authentication proof"), 400
    auth = store()
    with auth.lock:
        auth.prune()
        # Consume once, even if the signature is invalid. Never issue two sessions
        # from the same challenge, including concurrent verification requests.
        pending = auth.challenges.pop(nonce, None)
    if pending is None:
        return jsonify(error="Challenge expired or already used"), 401
    user_id, key, audience, _ = pending
    try:
        signature = decode_base64(data.get("signature"), 128)
        key.verify(signature, proof_bytes(user_id, nonce, audience), ec.ECDSA(hashes.SHA256()))
    except (ValueError, TypeError, InvalidSignature):
        return jsonify(error="Invalid authentication proof"), 401
    token = secrets.token_urlsafe(32)
    with auth.lock:
        auth.prune()
        if len(auth.sessions) >= auth.capacity or (user_id not in auth.devices and len(auth.devices) >= auth.capacity):
            return jsonify(error="Authentication capacity reached; retry later"), 429
        auth.devices[user_id] = key
        auth.sessions[hashlib.sha256(token.encode("ascii")).digest()] = (
            user_id, time.monotonic() + auth.session_ttl,
        )
    return jsonify(user_id=user_id, token=token, expires_in=auth.session_ttl)


def register_auth(app):
    app.extensions["device_auth"] = AuthStore(
        app.config.get("AUTH_SESSION_TTL", 3600), app.config.get("AUTH_CHALLENGE_TTL", 60),
    )
    app.register_blueprint(api)

    @app.before_request
    def authenticate():
        # Unknown paths/methods still use Flask's normal 404/405 handlers.
        if request.endpoint is None or request.endpoint == "api.health":
            return None
        if not request.is_secure and not app.config["ALLOW_INSECURE_HTTP"]:
            return jsonify(error="HTTPS is required"), 426
        if not app.config.get("AUTH_ORIGIN") and not app.config["ALLOW_INSECURE_HTTP"]:
            return jsonify(error="Server must configure CARRIEX_AUTH_ORIGIN"), 503
        if request.endpoint.startswith("auth."):
            return None
        session = store().session(request.headers.get("Authorization", ""))
        if session is None:
            # A notification credential must never authorize inbox retrieval,
            # acknowledgements, sending, or even issuance of another credential.
            if request.endpoint == "notifications.pending_count" and request.method in {"GET", "HEAD"}:
                from src.notifications import count_identity
                owner = count_identity(request.headers.get("Authorization", ""))
                if owner is None:
                    return jsonify(error="Device authentication required"), 401
                g.user_id, g.auth_expires_at = owner, time.monotonic()
            else:
                return jsonify(error="Device authentication required"), 401
        else:
            g.user_id, g.auth_expires_at = session
        path_user = (request.view_args or {}).get("user_id")
        if path_user is not None and path_user != g.user_id:
            return jsonify(error="Cannot access another device's messages"), 403

    @app.after_request
    def no_credentials_cache(response):
        if request.path.startswith(("/auth/", "/messages/")):
            response.headers["Cache-Control"] = "no-store"
        return response
