"""Signed group membership and opaque sender-key fan-out. No group secret reaches the relay."""
import base64
import hashlib
import json
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Blueprint, g, jsonify, request

from src.auth import valid_user_id
from src.store import send_event, store

api = Blueprint("groups", __name__)
FIELDS = {"version", "id", "revision", "epoch", "previous", "admin", "name", "members",
          "invited", "actor", "action", "target", "closed", "auth_key", "signature"}


class GroupError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def signing_bytes(s):
    title = base64.b64encode(s["name"].encode("utf-8")).decode("ascii")
    return (f"Carriex group state v1\n{s['id']}\n{s['revision']}\n{s['epoch']}\n{s['previous']}\n"
            f"{s['admin']}\n{title}\n{','.join(s['members'])}\n{','.join(s['invited'])}\n"
            f"{s['actor']}\n{s['action']}\n{s['target']}\n{int(s['closed'])}\n").encode("ascii")


def state_hash(s):
    return hashlib.sha256(signing_bytes(s)).hexdigest()


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def decode(value, maximum):
    try:
        if not isinstance(value, str) or len(value) > maximum * 2:
            raise ValueError()
        result = base64.b64decode(value, validate=True)
        if not result or len(result) > maximum or base64.b64encode(result).decode() != value:
            raise ValueError()
        return result
    except (ValueError, TypeError):
        raise GroupError("Invalid group encoding") from None


def validate_state(s):
    if not isinstance(s, dict) or set(s) != FIELDS:
        raise GroupError("Invalid group state fields")
    if type(s["version"]) is not int or s["version"] != 1 or not identifier(s["id"]) or any(
        type(s[k]) is not int or not 1 <= s[k] <= 4096 for k in ("revision", "epoch")
    ) or not valid_user_id(s["previous"]):
        raise GroupError("Invalid group version or revision")
    if any(not valid_user_id(s[k]) for k in ("admin", "actor")) or type(s["closed"]) is not bool:
        raise GroupError("Invalid group identity")
    if not isinstance(s["name"], str) or not s["name"].strip() or not 1 <= len(s["name"]) <= 80 or any(ord(c) < 32 for c in s["name"]):
        raise GroupError("Group name must have 1 to 80 characters without control characters")
    for field in ("members", "invited"):
        values = s[field]
        if (not isinstance(values, list) or len(values) > 32 or any(not valid_user_id(v) for v in values)
                or values != sorted(set(values))):
            raise GroupError("Group lists must contain at most 32 distinct, sorted device IDs")
    if set(s["members"]) & set(s["invited"]) or len(s["members"]) + len(s["invited"]) > 32:
        raise GroupError("At most 32 members and invitations combined are supported")
    if not isinstance(s["target"], str) or (s["target"] and not valid_user_id(s["target"])):
        raise GroupError("Invalid group target")
    if not isinstance(s["action"], str) or s["action"] not in {"create", "invite", "join", "remove", "leave", "decline", "close", "rename"}:
        raise GroupError("Invalid membership action")
    try:
        key_bytes = decode(s["auth_key"], 256)
        key = serialization.load_der_public_key(key_bytes)
        if (not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1)
                or hashlib.sha256(key_bytes).hexdigest() != s["actor"]):
            raise GroupError("Group signer does not match its device ID", 403)
        key.verify(decode(s["signature"], 80), signing_bytes(s), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise GroupError("Invalid membership signature", 403) from None


def transition(old, s):
    if old is None:
        if not (s["action"] == "create" and s["actor"] == s["admin"] and s["revision"] == s["epoch"] == 1
                and s["previous"] == "0" * 64 and s["members"] == [s["admin"]]
                and not s["invited"] and not s["closed"] and s["target"] == ""):
            raise GroupError("A group must start with its permanent admin as the only member")
        return
    if old["closed"] or s["revision"] != old["revision"] + 1 or s["previous"] != state_hash(old):
        raise GroupError("Group membership changed; synchronize and retry", 409)
    if any(s[k] != old[k] for k in ("id", "admin")):
        raise GroupError("The group admin and identity cannot be changed", 403)
    if s["action"] != "rename" and s["name"] != old["name"]:
        raise GroupError("Only an admin rename may change the group name", 403)
    members, invited = set(old["members"]), set(old["invited"])
    actor, target, action = s["actor"], s["target"], s["action"]
    closed = False
    if action == "rename" and actor == old["admin"] and target == "" and s["name"] != old["name"]:
        pass
    elif action == "invite" and actor == old["admin"] and target not in members | invited:
        invited.add(target)
    elif action == "join" and actor == target and actor in invited:
        invited.remove(actor)
        members.add(actor)
    elif action == "remove" and actor == old["admin"] and target != actor and target in members | invited:
        members.discard(target)
        invited.discard(target)
    elif action == "leave" and actor == target and actor in members and actor != old["admin"]:
        members.remove(actor)
    elif action == "decline" and actor == target and actor in invited:
        invited.remove(actor)
    elif action == "close" and actor == old["admin"] and target == "":
        members.clear()
        invited.clear()
        closed = True
    else:
        raise GroupError("This device cannot make that membership change", 403)
    epoch = old["epoch"] + (sorted(members) != old["members"])
    if s["members"] != sorted(members) or s["invited"] != sorted(invited) or s["epoch"] != epoch or s["closed"] != closed:
        raise GroupError("Membership transition or sender-key epoch does not match the action", 409)


def current(db, group_id, member=False):
    row = db.execute("SELECT body FROM groups WHERE id=?", (group_id,)).fetchone()
    if row is None:
        raise GroupError("Group does not exist", 404)
    s = json.loads(row[0])
    if member and (s["closed"] or g.user_id not in s["members"]):
        raise GroupError("Current group membership required", 403)
    return s


def next_arrival(db):
    db.execute("UPDATE message_sequence SET value=value+1 WHERE id=1")
    return db.execute("SELECT value FROM message_sequence WHERE id=1").fetchone()[0]


def admission_bytes(s):
    return (f"Carriex group admission v1\n{s['group_id']}\n{s['member']}\n"
            f"{s['revision']}\n{s['state_hash']}\n{s['admin']}\n").encode("ascii")


def personal_invitation(db, group_id, owner):
    row = db.execute("SELECT body FROM group_events WHERE group_id=? AND json_extract(body,'$.action')='invite' AND json_extract(body,'$.target')=? ORDER BY revision DESC LIMIT 1", (group_id, owner)).fetchone()
    return json.loads(row[0]) if row else None


def periods(db, group_id, owner):
    return [dict(row) for row in db.execute("SELECT first_revision,last_revision FROM group_periods WHERE group_id=? AND owner=? ORDER BY first_revision", (group_id, owner))]


@api.errorhandler(GroupError)
def group_error(error):
    return jsonify(error=str(error)), error.status


@api.get("/groups")
def list_groups():
    with store().connect() as db:
        rows = db.execute("SELECT a.group_id,coalesce(a.last_revision,g.revision) AS revision FROM group_access a JOIN groups g ON g.id=a.group_id WHERE a.owner=? ORDER BY a.group_id", (g.user_id,)).fetchall()
    return jsonify(protocol=2, groups=[dict(row) for row in rows])


@api.post("/groups/state")
def change_state():
    s = request.get_json(silent=True)
    validate_state(s)
    if s["actor"] != g.user_id:
        raise GroupError("Membership signer must be the authenticated device", 403)
    with store().connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT body FROM groups WHERE id=?", (s["id"],)).fetchone()
        old = json.loads(row[0]) if row else None
        if old and state_hash(old) == state_hash(s):
            return jsonify(status="ok")  # Lost-response retry; signature encoding may differ.
        transition(old, s)
        before = set(old["members"] + old["invited"]) if old else set()
        after = set(s["members"] + s["invited"])
        for owner in after - before:
            if db.execute("SELECT count(*) FROM group_access WHERE owner=?", (owner,)).fetchone()[0] >= 64:
                raise GroupError("A device can participate in at most 64 groups", 429)
        if not old and db.execute("SELECT count(*) FROM groups").fetchone()[0] >= 4096:
            raise GroupError("Group capacity reached", 429)
        count, size = db.execute("SELECT count(*),coalesce(sum(length(body)),0) FROM group_events").fetchone()
        if count >= 50000 or size > 64 * 1024 * 1024:
            raise GroupError("Group membership storage capacity reached", 429)
        body = json.dumps(s, separators=(",", ":"))
        db.execute("INSERT INTO groups VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,body=excluded.body", (s["id"], s["revision"], body))
        db.execute("INSERT INTO group_events VALUES (?,?,?)", (s["id"], s["revision"], body))
        old_members = set(old["members"]) if old else set()
        for owner in set(s["members"]) - old_members:
            db.execute("INSERT INTO group_periods VALUES (?,?,?,NULL)", (s["id"], owner, s["revision"]))
        for owner in old_members - set(s["members"]):
            db.execute("UPDATE group_periods SET last_revision=? WHERE group_id=? AND owner=? AND last_revision IS NULL", (s["revision"], s["id"], owner))
        for owner in before - after:
            db.execute("UPDATE group_access SET last_revision=?,invited=0 WHERE group_id=? AND owner=?", (s["revision"], s["id"], owner))
            db.execute("UPDATE group_deliveries SET acked=-1 WHERE group_id=? AND recipient=? AND acked=0", (s["id"], owner))
            db.execute("DELETE FROM group_keys WHERE group_id=? AND recipient=?", (s["id"], owner))
        for owner in after:
            arrival = next_arrival(db) if owner in s["invited"] and owner not in before else 0
            db.execute("INSERT INTO group_access VALUES (?,?,NULL,?,?) ON CONFLICT(group_id,owner) DO UPDATE SET last_revision=NULL,invited=excluded.invited,arrival=CASE WHEN excluded.arrival>0 THEN excluded.arrival ELSE group_access.arrival END",
                       (s["id"], owner, int(owner in s["invited"]), arrival))
        if old and s["epoch"] != old["epoch"]:
            # Keep old receiving packets only for their original recipients and
            # only through the message retention window. They never authorize sending.
            db.execute("UPDATE group_keys SET expires=? WHERE group_id=? AND expires=0", (int(time.time()) + store().ttl_seconds, s["id"]))
        if s["closed"]:
            for table in ("group_keys", "group_deliveries", "group_messages"):
                db.execute(f"DELETE FROM {table} WHERE group_id=?", (s["id"],))
    for owner in before | after:
        send_event(owner, {"type": "groups"})
    return jsonify(status="ok")


@api.get("/groups/<group_id>/events")
def events(group_id):
    after = request.args.get("after", "0")
    if not after.isascii() or not after.isdigit() or len(after) > 5:
        raise GroupError("Invalid group revision")
    with store().connect() as db:
        access = db.execute("SELECT last_revision FROM group_access WHERE group_id=? AND owner=?", (group_id, g.user_id)).fetchone()
        if access is None:
            raise GroupError("Group invitation or membership required", 403)
        # Filtering lives at the authorization boundary, including after=0 and
        # deliberately old cursors. Invitations never grant access to activity.
        rows = db.execute("""SELECT e.body FROM group_events e WHERE e.group_id=? AND e.revision>?
            AND EXISTS (SELECT 1 FROM group_periods p WHERE p.group_id=e.group_id AND p.owner=?
                AND e.revision>=p.first_revision AND (p.last_revision IS NULL OR e.revision<=p.last_revision))
            ORDER BY e.revision LIMIT 100""", (group_id, int(after), g.user_id)).fetchall()
        visible = [json.loads(row[0]) for row in rows]
        checkpoints = []
        for event in visible:
            if event["action"] == "join" and event["target"] == g.user_id:
                checkpoint = db.execute("SELECT body FROM group_admissions WHERE group_id=? AND revision=? AND member=?", (group_id, event["revision"], g.user_id)).fetchone()
                if checkpoint:
                    checkpoints.append(json.loads(checkpoint[0]))
        terminal = None
        if access[0] is not None:
            row = db.execute("SELECT body FROM group_events WHERE group_id=? AND revision=?", (group_id, access[0])).fetchone()
            terminal = json.loads(row[0]) if row else None
        return jsonify(protocol=2, events=visible, periods=periods(db, group_id, g.user_id),
                       invitation=personal_invitation(db, group_id, g.user_id), terminal=terminal, admissions=checkpoints)


@api.get("/groups/<group_id>/join-proposal")
def join_proposal(group_id):
    return invitation_proposal(group_id, "join")


@api.get("/groups/<group_id>/decline-proposal")
def decline_proposal(group_id):
    return invitation_proposal(group_id, "decline")


def invitation_proposal(group_id, action):
    with store().connect() as db:
        s = current(db, group_id)
        if s["closed"] or g.user_id not in s["invited"]:
            raise GroupError("A pending invitation is required", 403)
        # A template for this device's own join, not the preceding event. No
        # historical actor/action/target or former roster is disclosed.
        proposal = dict(s, revision=s["revision"] + 1, epoch=s["epoch"] + int(action == "join"),
                        previous=state_hash(s), members=sorted(s["members"] + ([g.user_id] if action == "join" else [])),
                        invited=[owner for owner in s["invited"] if owner != g.user_id],
                        actor=g.user_id, action=action, target=g.user_id)
        proposal.pop("auth_key")
        proposal.pop("signature")
    return jsonify(state=proposal)


@api.post("/groups/<group_id>/admissions")
def publish_admissions(group_id):
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("admissions"), list) or not 1 <= len(body["admissions"]) <= 100:
        raise GroupError("Invalid group admissions")
    recipients = set()
    with store().connect() as db:
        db.execute("BEGIN IMMEDIATE")
        group = current(db, group_id)
        if g.user_id != group["admin"]:
            raise GroupError("Only the permanent admin may confirm admissions", 403)
        for checkpoint in body["admissions"]:
            if (not isinstance(checkpoint, dict) or set(checkpoint) != {"version", "group_id", "member", "revision", "state_hash", "admin", "auth_key", "signature"}
                    or type(checkpoint["version"]) is not int or checkpoint["version"] != 1
                    or type(checkpoint["revision"]) is not int or not 1 <= checkpoint["revision"] <= 4096
                    or checkpoint["group_id"] != group_id or checkpoint["admin"] != g.user_id
                    or not valid_user_id(checkpoint["member"]) or not valid_user_id(checkpoint["state_hash"])):
                raise GroupError("Invalid admission checkpoint")
            row = db.execute("SELECT body FROM group_events WHERE group_id=? AND revision=?", (group_id, checkpoint["revision"])).fetchone()
            joined = json.loads(row[0]) if row else None
            if not joined or joined["action"] != "join" or joined["target"] != checkpoint["member"] or state_hash(joined) != checkpoint["state_hash"]:
                raise GroupError("Admission must confirm the exact accepted join", 409)
            try:
                public = decode(checkpoint["auth_key"], 256)
                key = serialization.load_der_public_key(public)
                if (not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1)
                        or hashlib.sha256(public).hexdigest() != group["admin"]):
                    raise GroupError("Admission signer must be the permanent admin", 403)
                key.verify(decode(checkpoint["signature"], 80), admission_bytes(checkpoint), ec.ECDSA(hashes.SHA256()))
            except (InvalidSignature, ValueError):
                raise GroupError("Invalid admission signature", 403) from None
            db.execute("INSERT OR IGNORE INTO group_admissions VALUES (?,?,?,?)", (group_id, checkpoint["revision"], checkpoint["member"], json.dumps(checkpoint, separators=(",", ":"))))
            recipients.add(checkpoint["member"])
    for owner in recipients:
        send_event(owner, {"type": "groups"})
    return jsonify(status="ok")


@api.route("/groups/<group_id>/keys", methods=["GET", "POST"])
def sender_keys(group_id):
    with store().connect() as db:
        db.execute("BEGIN IMMEDIATE")
        s = current(db, group_id, member=True)
        db.execute("DELETE FROM group_keys WHERE expires>0 AND expires<=?", (int(time.time()),))
        if request.method == "GET":
            value = request.args.get("epoch", str(s["epoch"]))
            if not value.isascii() or not value.isdigit() or len(value) > 4 or not 1 <= int(value) <= s["epoch"]:
                raise GroupError("Invalid sender-key epoch")
            epoch = int(value)
            rows = db.execute("SELECT sender,recipient,id,wire FROM group_keys WHERE group_id=? AND epoch=? AND recipient=? ORDER BY sender", (group_id, epoch, g.user_id)).fetchall()
            return jsonify(epoch=epoch, packets=[dict(row) for row in rows])
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or type(body.get("epoch")) is not int or body["epoch"] != s["epoch"]:
            raise GroupError("Sender keys must use the current membership epoch", 409)
        packets = body.get("packets")
        if not isinstance(packets, list) or len(packets) != len(s["members"]) - 1:
            raise GroupError("Distribute a sender key to every other current member")
        recipients = []
        for packet in packets:
            if (not isinstance(packet, dict) or set(packet) != {"recipient", "id", "wire"}
                    or not identifier(packet["id"]) or not valid_user_id(packet["recipient"])):
                raise GroupError("Invalid encrypted sender-key packet")
            decode(packet["wire"], 16 * 1024)
            recipients.append(packet["recipient"])
        if sorted(recipients) != sorted(set(s["members"]) - {g.user_id}):
            raise GroupError("Sender keys may go only to all current members", 403)
        additions = []
        for packet in packets:
            old = db.execute("SELECT id,wire FROM group_keys WHERE group_id=? AND epoch=? AND sender=? AND recipient=?", (group_id, s["epoch"], g.user_id, packet["recipient"])).fetchone()
            if old and tuple(old) != (packet["id"], packet["wire"]):
                raise GroupError("A published sender-key distribution is immutable within its epoch", 409)
            if old is None:
                additions.append(packet)
        count, size = db.execute("SELECT count(*),coalesce(sum(length(wire)),0) FROM group_keys").fetchone()
        if count + len(additions) > 100000 or size + sum(len(p["wire"]) for p in additions) > 128 * 1024 * 1024:
            raise GroupError("Sender-key packet storage capacity reached", 429)
        for packet in additions:
            db.execute("INSERT OR IGNORE INTO group_keys(group_id,epoch,sender,recipient,id,wire) VALUES (?,?,?,?,?,?)", (group_id, s["epoch"], g.user_id, packet["recipient"], packet["id"], packet["wire"]))
    for owner in s["members"]:
        if owner != g.user_id:
            send_event(owner, {"type": "groups"})
    return jsonify(status="ok")


@api.route("/groups/<group_id>/messages", methods=["GET", "POST"])
def messages(group_id):
    with store().connect() as db:
        db.execute("BEGIN IMMEDIATE")
        relay = store()
        db.execute("DELETE FROM group_deliveries WHERE expires<=?", (int(time.time()),))
        db.execute("DELETE FROM group_messages WHERE expires<=?", (int(time.time()),))
        s = current(db, group_id, member=True)
        if request.method == "GET":
            rows = db.execute("SELECT m.id,m.sender,m.epoch,m.wire FROM group_deliveries d JOIN group_messages m ON m.group_id=d.group_id AND m.id=d.id WHERE d.group_id=? AND d.recipient=? AND d.acked=0 ORDER BY d.arrival LIMIT 8", (group_id, g.user_id)).fetchall()
            return jsonify(messages=[dict(row) for row in rows])
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or type(body.get("epoch")) is not int or body["epoch"] != s["epoch"]:
            raise GroupError("Group membership changed; rotate sender keys before sending", 409)
        if not identifier(body.get("id")):
            raise GroupError("Invalid group message ID")
        decode(body.get("wire"), 128 * 1024)
        key_count = db.execute("SELECT count(*) FROM group_keys WHERE group_id=? AND epoch=? AND sender=?", (group_id, s["epoch"], g.user_id)).fetchone()[0]
        if key_count != len(s["members"]) - 1:
            raise GroupError("Redistribute fresh sender keys before sending", 409)
        digest = hashlib.sha256(body["wire"].encode("ascii")).hexdigest()
        existing = db.execute("SELECT sender,epoch,digest FROM group_messages WHERE group_id=? AND id=?", (group_id, body["id"])).fetchone()
        if existing:
            if tuple(existing) != (g.user_id, s["epoch"], digest):
                raise GroupError("Group message ID already has different content", 409)
            return jsonify(status="ok")
        count, size = db.execute("SELECT count(*),coalesce(sum(length(wire)),0) FROM group_messages").fetchone()
        if count >= 25000 or size + len(body["wire"]) > 128 * 1024 * 1024:
            raise GroupError("Group message storage capacity reached", 429)
        if db.execute("SELECT count(*) FROM group_messages WHERE group_id=? AND wire!=''", (group_id,)).fetchone()[0] >= 1000:
            raise GroupError("Group message queue is full", 429)
        expires = int(time.time()) + relay.ttl_seconds
        db.execute("INSERT INTO group_messages(group_id,id,sender,epoch,wire,expires,digest) VALUES (?,?,?,?,?,?,?)", (group_id, body["id"], g.user_id, s["epoch"], body["wire"], expires, digest))
        for owner in set(s["members"]) - {g.user_id}:
            db.execute("INSERT INTO group_deliveries VALUES (?,?,?,0,?,?)", (group_id, body["id"], owner, next_arrival(db), expires))
    for owner in set(s["members"]) - {g.user_id}:
        send_event(owner, {"type": "groups"})
    return jsonify(status="ok")


@api.post("/groups/<group_id>/ack")
def acknowledge(group_id):
    data = request.get_json(silent=True)
    ids = data.get("ids") if isinstance(data, dict) else None
    if not isinstance(ids, list) or len(ids) > 64 or any(not identifier(i) for i in ids):
        raise GroupError("Invalid group acknowledgement")
    with store().connect() as db:
        current(db, group_id, member=True)
        for identity in ids:
            db.execute("UPDATE group_deliveries SET acked=1 WHERE group_id=? AND id=? AND recipient=? AND acked=0", (group_id, identity, g.user_id))
            db.execute("UPDATE group_messages SET wire='' WHERE group_id=? AND id=? AND NOT EXISTS (SELECT 1 FROM group_deliveries WHERE group_id=? AND id=? AND acked=0)", (group_id, identity, group_id, identity))
    return jsonify(status="ok")


@api.get("/groups/<group_id>/statuses")
def statuses(group_id):
    with store().connect() as db:
        current(db, group_id, member=True)
        rows = db.execute("SELECT m.id,CASE WHEN EXISTS (SELECT 1 FROM group_deliveries d WHERE d.group_id=m.group_id AND d.id=m.id AND d.acked!=1) THEN 'sent' ELSE 'received' END AS state FROM group_messages m WHERE m.group_id=? AND m.sender=? ORDER BY m.rowid DESC LIMIT 500", (group_id, g.user_id)).fetchall()
    return jsonify(statuses=[dict(row) for row in rows])


def pending_count(owner):
    with store().connect() as db:
        messages = db.execute("SELECT count(*),coalesce(max(arrival),0) FROM group_deliveries WHERE recipient=? AND acked=0 AND expires>?", (owner, int(time.time()))).fetchone()
        invitations = db.execute("SELECT count(*),coalesce(max(arrival),0) FROM group_access WHERE owner=? AND invited=1", (owner,)).fetchone()
    return messages[0] + invitations[0], max(messages[1], invitations[1])


def register_groups(app):
    with app.app_context(), store().connect() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY,revision INTEGER NOT NULL,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS group_events (group_id TEXT NOT NULL,revision INTEGER NOT NULL,body TEXT NOT NULL,PRIMARY KEY(group_id,revision));
            CREATE TABLE IF NOT EXISTS group_access (group_id TEXT NOT NULL,owner TEXT NOT NULL,last_revision INTEGER,invited INTEGER NOT NULL,arrival INTEGER NOT NULL,PRIMARY KEY(group_id,owner));
            CREATE TABLE IF NOT EXISTS group_admissions (group_id TEXT NOT NULL,revision INTEGER NOT NULL,member TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(group_id,revision));
            CREATE INDEX IF NOT EXISTS group_owner ON group_access(owner,invited,arrival);
            CREATE TABLE IF NOT EXISTS group_keys (group_id TEXT NOT NULL,epoch INTEGER NOT NULL,sender TEXT NOT NULL,recipient TEXT NOT NULL,id TEXT NOT NULL,wire TEXT NOT NULL,expires INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(group_id,epoch,sender,recipient));
            CREATE TABLE IF NOT EXISTS group_messages (group_id TEXT NOT NULL,id TEXT NOT NULL,sender TEXT NOT NULL,epoch INTEGER NOT NULL,wire TEXT NOT NULL,expires INTEGER NOT NULL,digest TEXT NOT NULL DEFAULT '',PRIMARY KEY(group_id,id));
            CREATE TABLE IF NOT EXISTS group_deliveries (group_id TEXT NOT NULL,id TEXT NOT NULL,recipient TEXT NOT NULL,acked INTEGER NOT NULL,arrival INTEGER NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(group_id,id,recipient));
            CREATE INDEX IF NOT EXISTS group_pending ON group_deliveries(recipient,acked,expires,arrival);
        """)
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='group_periods'").fetchone() is None:
            # Reconstruct exact historical participation intervals once when upgrading.
            db.execute("CREATE TABLE group_periods (group_id TEXT NOT NULL,owner TEXT NOT NULL,first_revision INTEGER NOT NULL,last_revision INTEGER,PRIMARY KEY(group_id,owner,first_revision))")
            previous = {}
            for row in db.execute("SELECT group_id,revision,body FROM group_events ORDER BY group_id,revision").fetchall():
                state = json.loads(row[2])
                before = previous.get(row[0], set())
                after = set(state["members"])
                for owner in after - before:
                    db.execute("INSERT INTO group_periods VALUES (?,?,?,NULL)", (row[0], owner, row[1]))
                for owner in before - after:
                    db.execute("UPDATE group_periods SET last_revision=? WHERE group_id=? AND owner=? AND last_revision IS NULL", (row[1], row[0], owner))
                previous[row[0]] = after
        if "expires" not in {row[1] for row in db.execute("PRAGMA table_info(group_keys)")}:
            db.execute("ALTER TABLE group_keys ADD COLUMN expires INTEGER NOT NULL DEFAULT 0")
        if "digest" not in {row[1] for row in db.execute("PRAGMA table_info(group_messages)")}:
            db.execute("ALTER TABLE group_messages ADD COLUMN digest TEXT NOT NULL DEFAULT ''")
            for row in db.execute("SELECT group_id,id,wire FROM group_messages").fetchall():
                db.execute("UPDATE group_messages SET digest=? WHERE group_id=? AND id=?", (hashlib.sha256(row[2].encode("ascii")).hexdigest(), row[0], row[1]))
        db.execute("CREATE INDEX IF NOT EXISTS group_key_expiry ON group_keys(expires)")
        db.execute("CREATE INDEX IF NOT EXISTS group_message_expiry ON group_messages(expires)")
    app.register_blueprint(api)

    @app.after_request
    def no_group_cache(response):
        if request.endpoint and request.endpoint.startswith("groups."):
            response.headers["Cache-Control"] = "no-store"
        return response
