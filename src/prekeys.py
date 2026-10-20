"""Public X3DH directory. Claims consume a prekey atomically; no private keys."""
import base64
import hashlib
import json
import re
import time

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Blueprint, current_app, g, jsonify, request

from src.auth import decode_base64, valid_user_id
from src.store import store

api = Blueprint("prekeys", __name__)


def key_bytes(value, size):
    raw = decode_base64(value, 512)
    if len(raw) != size or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("Invalid key encoding")
    return raw


def key_id(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise ValueError("Invalid prekey ID")
    return value


def validate_bundle(data, owner):
    if not isinstance(data, dict) or data.get("version") != 2:
        raise ValueError("X3DH version 2 is required")
    identity = key_bytes(data.get("identity_key"), 32)
    auth_bytes = decode_base64(data.get("auth_key"), 256)
    auth = serialization.load_der_public_key(auth_bytes)
    if not isinstance(auth, ec.EllipticCurvePublicKey) or not isinstance(auth.curve, ec.SECP256R1):
        raise ValueError("P-256 authentication key required")
    canonical = auth.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if canonical != auth_bytes or hashlib.sha256(canonical).hexdigest() != owner:
        raise ValueError("Identity does not belong to authenticated device")
    proof = f"Carriex encryption identity v2\n{owner}\n{data['identity_key']}".encode("ascii")
    auth.verify(decode_base64(data.get("binding"), 128), proof, ec.ECDSA(hashes.SHA256()))
    # Clients verify XEdDSA. The relay only validates its encoding, not trust.
    signed = data.get("signed_prekey")
    if not isinstance(signed, dict):
        raise ValueError("Signed prekey required")
    key_id(signed.get("id"))
    key_bytes(signed.get("key"), 32)
    key_bytes(signed.get("signature"), 64)
    prekeys = data.get("one_time_prekeys")
    if not isinstance(prekeys, list) or len(prekeys) > 100:
        raise ValueError("At most 100 one-time prekeys per upload")
    seen = set()
    for prekey in prekeys:
        if not isinstance(prekey, dict) or key_id(prekey.get("id")) in seen:
            raise ValueError("Duplicate or invalid prekey ID")
        seen.add(prekey["id"])
        key_bytes(prekey.get("key"), 32)
    revision = data.get("revision")
    if type(revision) is not int or not 1 <= revision <= 0x7fffffff:
        raise ValueError("Update client: publication revision required")
    key_id(data.get("publication_id"))
    if any(not prekey["id"].startswith(f"{revision:08x}") for prekey in prekeys):
        raise ValueError("Prekey IDs must belong to this publication revision")
    return {"version": 2, "user_id": owner, "identity_key": base64.b64encode(identity).decode("ascii"),
            "auth_key": data["auth_key"], "binding": data["binding"],
            "signed_prekey": {field: signed[field] for field in ("id", "key", "signature")}}, prekeys


@api.post("/prekeys")
def publish():
    data = request.get_json(silent=True)
    try:
        bundle, prekeys = validate_bundle(data, g.user_id)
    except (ValueError, TypeError, KeyError, InvalidSignature, UnsupportedAlgorithm):
        return jsonify(error="Invalid signed device prekey bundle"), 400
    with store().connect() as db:
        db.execute("BEGIN IMMEDIATE")
        old = db.execute("SELECT * FROM prekey_bundles WHERE owner=?", (g.user_id,)).fetchone()
        if old and json.loads(old["bundle"])["identity_key"] != bundle["identity_key"]:
            return jsonify(error="Encryption identity changed; use a new device identity"), 409
        manifest = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        previous_revision = old["revision"] if old else 0
        if data["revision"] == previous_revision:
            previous_manifest = old["manifest"]
            if previous_manifest and previous_manifest.startswith("{"):
                previous_manifest = hashlib.sha256(previous_manifest.encode("utf-8")).hexdigest()
            if previous_manifest != manifest:
                return jsonify(error="Publication revision already has different content"), 409
            store().statistics.record(db, "prekeys.publication_retries")
            return jsonify(json.loads(old["receipt"])), 200
        # A phone can retain its monotonic counter when a fresh relay has no directory.
        if old is not None and data["revision"] != previous_revision + 1:
            return jsonify(error="Stale publication; synchronize prekey status"), 409
        now = int(time.time())
        db.execute("DELETE FROM one_time_prekeys WHERE claimed=1 OR expires_at<=?", (now,))
        available = db.execute("SELECT count(*) FROM one_time_prekeys WHERE owner=? AND claimed=0",
                               (g.user_id,)).fetchone()[0]
        if available + len(prekeys) > 200:
            return jsonify(error="Too many available prekeys"), 429
        if old is None and db.execute("SELECT count(*) FROM prekey_bundles").fetchone()[0] >= current_app.config.get("PREKEY_OWNER_LIMIT", 4096):
            return jsonify(error="Prekey directory capacity reached"), 429
        if db.execute("SELECT count(*) FROM one_time_prekeys").fetchone()[0] + len(prekeys) > current_app.config.get("PREKEY_GLOBAL_LIMIT", 20000):
            return jsonify(error="Global prekey capacity reached"), 429
        expires = now + 7 * 86400
        receipt = dict(status="ok", revision=data["revision"], publication_id=data["publication_id"],
                       signed_prekey_id=bundle["signed_prekey"]["id"], accepted_at=now,
                       prekeys_expire_at=expires, message_ttl_seconds=store().ttl_seconds)
        db.execute("INSERT INTO prekey_bundles(owner,bundle,revision,manifest,receipt) VALUES (?,?,?,?,?) ON CONFLICT(owner) DO UPDATE SET bundle=excluded.bundle,revision=excluded.revision,manifest=excluded.manifest,receipt=excluded.receipt",
                   (g.user_id, json.dumps(bundle), data["revision"], manifest, json.dumps(receipt)))
        for prekey in prekeys:
            db.execute("INSERT INTO one_time_prekeys(owner,id,public_key,claimed,expires_at) VALUES (?,?,?,0,?)",
                       (g.user_id, prekey["id"], prekey["key"], expires))
        store().statistics.record(db, "prekeys.publications")
        store().statistics.record(db, "prekeys.published", len(prekeys), len(prekeys))
    return jsonify(receipt), 200


@api.get("/prekeys/status")
def status():
    with store().connect() as db:
        db.execute("DELETE FROM one_time_prekeys WHERE claimed=1 OR expires_at <= ?", (int(time.time()),))
        count = db.execute("SELECT count(*) FROM one_time_prekeys WHERE owner=? AND claimed=0", (g.user_id,)).fetchone()[0]
        row = db.execute("SELECT revision,receipt FROM prekey_bundles WHERE owner=?", (g.user_id,)).fetchone()
    return jsonify(available=count, message_ttl_seconds=store().ttl_seconds, revision=row[0] if row else 0,
                   receipt=json.loads(row[1]) if row and row[1] else None), 200


@api.post("/prekeys/<peer>/claim")
def claim(peer):
    if not valid_user_id(peer) or peer == g.user_id:
        return jsonify(error="Invalid peer"), 400
    now = int(time.time())
    with store().connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT bundle FROM prekey_bundles WHERE owner=?", (peer,)).fetchone()
        if row is None:
            return jsonify(error="Contact has not published X3DH keys; update and connect their app first"), 404
        # Durable per-device and per-target limits survive restart.
        db.execute("DELETE FROM prekey_claim_limits WHERE minute < ?", (now // 60 - 1,))
        limits = (("sender:" + g.user_id, 30), ("target:" + peer, 100))
        for name, maximum in limits:
            used = db.execute("SELECT count FROM prekey_claim_limits WHERE name=? AND minute=?", (name, now // 60)).fetchone()
            if used and used[0] >= maximum:
                store().statistics.record(db, "prekeys.rate_limited")
                return jsonify(error="Prekey claim rate limit reached"), 429
        for name, _ in limits:
            db.execute("INSERT INTO prekey_claim_limits(name,minute,count) VALUES (?,?,1) ON CONFLICT(name,minute) DO UPDATE SET count=count+1",
                       (name, now // 60))
        bundle = json.loads(row[0])
        key = db.execute("SELECT id,public_key FROM one_time_prekeys WHERE owner=? AND claimed=0 AND expires_at>? ORDER BY rowid LIMIT 1", (peer, now)).fetchone()
        bundle["one_time_prekey"] = None
        if key:
            db.execute("DELETE FROM one_time_prekeys WHERE owner=? AND id=?", (peer, key[0]))
            bundle["one_time_prekey"] = {"id": key[0], "key": key[1]}
        store().statistics.record(db, "prekeys.claimed" if key else "prekeys.claims_without_opk")
    return jsonify(bundle), 200


def register_prekeys(app):
    with app.app_context(), store().connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS prekey_bundles (owner TEXT PRIMARY KEY, bundle TEXT NOT NULL)")
        columns = {row[1] for row in db.execute("PRAGMA table_info(prekey_bundles)")}
        for name, definition in (("revision", "INTEGER NOT NULL DEFAULT 0"), ("manifest", "TEXT"), ("receipt", "TEXT")):
            if name not in columns:
                db.execute(f"ALTER TABLE prekey_bundles ADD COLUMN {name} {definition}")
        for row in db.execute("SELECT owner,manifest FROM prekey_bundles WHERE manifest LIKE '{%'").fetchall():
            db.execute("UPDATE prekey_bundles SET manifest=? WHERE owner=?",
                       (hashlib.sha256(row["manifest"].encode("utf-8")).hexdigest(), row["owner"]))
        db.execute("CREATE TABLE IF NOT EXISTS one_time_prekeys (owner TEXT NOT NULL,id TEXT NOT NULL,public_key TEXT NOT NULL,claimed INTEGER NOT NULL,expires_at INTEGER NOT NULL,PRIMARY KEY(owner,id))")
        db.execute("CREATE TABLE IF NOT EXISTS prekey_claim_limits (name TEXT NOT NULL,minute INTEGER NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(name,minute))")
        db.execute("CREATE INDEX IF NOT EXISTS prekey_expiry ON one_time_prekeys(expires_at)")
        db.execute("DELETE FROM one_time_prekeys WHERE claimed=1 OR expires_at<=?", (int(time.time()),))
    app.register_blueprint(api)

    @app.after_request
    def no_prekey_cache(response):
        if request.path.startswith("/prekeys"):
            response.headers["Cache-Control"] = "no-store"
        return response
