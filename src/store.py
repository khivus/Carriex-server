"""Durable, opaque message queue. A recipient acknowledgement retires ciphertext."""
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from flask import current_app
from src.statistics import RelayStatistics, record


websocket_connections = {}
store_lock = Lock()


class MessageTooLargeError(ValueError):
    pass


class MessageStore:
    def __init__(self, path, ttl_seconds=30 * 24 * 3600, statistics=None):
        self.path = str(path)
        self.ttl_seconds = int(ttl_seconds)
        self.statistics = statistics or RelayStatistics()
        if self.ttl_seconds <= 0:
            raise ValueError("MESSAGE_TTL_SECONDS must be positive")
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY, sender TEXT NOT NULL, recipient TEXT NOT NULL,
                ciphertext TEXT, created_at TEXT NOT NULL, expires_at INTEGER NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('queued', 'received')),
                receipt_visible INTEGER NOT NULL DEFAULT 1
            )""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(messages)")}
            if "arrival" not in columns:
                db.execute("ALTER TABLE messages ADD COLUMN arrival INTEGER NOT NULL DEFAULT 0")
            if "viewed" not in columns:
                db.execute("ALTER TABLE messages ADD COLUMN viewed INTEGER NOT NULL DEFAULT 0")
            db.execute("CREATE INDEX IF NOT EXISTS inbox_counts ON messages(recipient,state,expires_at,arrival)")
            db.execute("DROP INDEX IF EXISTS inbox")
            db.execute("CREATE TABLE IF NOT EXISTS message_sequence (id INTEGER PRIMARY KEY CHECK(id=1),value INTEGER NOT NULL)")
            db.execute("INSERT OR IGNORE INTO message_sequence VALUES (1,0)")
            db.execute("CREATE INDEX IF NOT EXISTS outbox ON messages(sender, expires_at)")
            db.execute("CREATE TABLE IF NOT EXISTS inbox_policy (owner TEXT PRIMARY KEY, contacts TEXT NOT NULL, blocked TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS quarantined_ids (id TEXT PRIMARY KEY)")
            self.statistics.initialize(db)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def prune(self, db):
        if self.statistics.enabled:
            count = db.execute("SELECT count(*) FROM messages WHERE expires_at<=? AND state='queued'", (int(time.time()),)).fetchone()[0]
            self.statistics.record(db, "messages.expired", count, count)
        db.execute("DELETE FROM messages WHERE expires_at <= ?", (int(time.time()),))
        db.execute("DELETE FROM quarantined_ids WHERE NOT EXISTS (SELECT 1 FROM messages WHERE messages.id=quarantined_ids.id)")

    def enqueue(self, sender, recipient, ciphertext, message_id=None):
        message_id = message_id or uuid.uuid4().hex
        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.prune(db)
            policy = db.execute("SELECT contacts,blocked FROM inbox_policy WHERE owner=?", (recipient,)).fetchone()
            contacts, blocked = (set(json.loads(policy[0])), set(json.loads(policy[1]))) if policy else (None, set())
            if sender in blocked:
                raise ValueError("Recipient is not accepting messages from this device")
            existing = db.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()
            if existing:
                if (existing["sender"], existing["recipient"]) != (sender, recipient):
                    raise ValueError("Message ID already belongs to another route")
                if existing["ciphertext"] is not None and existing["ciphertext"] != ciphertext:
                    raise ValueError("Message ID already has different content")
                self.statistics.record(db, "messages.duplicate_submissions")
            else:
                size = len(ciphertext.encode("utf-8"))
                if size > 256 * 1024:
                    raise MessageTooLargeError("Encrypted message exceeds 256 KiB")
                total, stored_bytes = db.execute("SELECT count(*),coalesce(sum(length(CAST(ciphertext AS BLOB))),0) FROM messages").fetchone()
                if total >= 50000 or stored_bytes + size > 128 * 1024 * 1024:
                    raise OverflowError("Server message storage capacity reached")
                recipient_bytes = db.execute("SELECT coalesce(sum(length(CAST(ciphertext AS BLOB))),0) FROM messages WHERE recipient=?", (recipient,)).fetchone()[0]
                if recipient_bytes + size > 16 * 1024 * 1024:
                    raise OverflowError("Recipient storage capacity reached")
                if policy:
                    sender_count = db.execute("SELECT count(*) FROM messages WHERE recipient=? AND sender=? AND state='queued'", (recipient, sender)).fetchone()[0]
                    if sender_count >= (64 if sender in contacts else 2):
                        raise OverflowError("Pending messages from this sender reached their limit")
                    if sender not in contacts:
                        unknown = db.execute("SELECT sender FROM messages WHERE recipient=? AND state='queued'", (recipient,)).fetchall()
                        if sum(row[0] not in contacts for row in unknown) >= 32:
                            raise OverflowError("Message request queue is full")
                count = db.execute("SELECT count(*) FROM messages WHERE recipient=? AND state='queued'", (recipient,)).fetchone()[0]
                if count >= 1000:
                    raise OverflowError("Recipient queue is full")
                db.execute("UPDATE message_sequence SET value=value+1 WHERE id=1")
                arrival = db.execute("SELECT value FROM message_sequence WHERE id=1").fetchone()[0]
                db.execute("INSERT INTO messages(id,sender,recipient,ciphertext,created_at,expires_at,state,arrival) VALUES (?,?,?,?,?,?,?,?)", (
                    message_id, sender, recipient, ciphertext,
                    datetime.now(timezone.utc).isoformat(), now + self.ttl_seconds, "queued", arrival,
                ))
                self.statistics.record(db, "messages.accepted")
                self.statistics.record(db, "messages.size_bytes", size)
            count = db.execute("SELECT count(*) FROM messages WHERE recipient=? AND state='queued'", (recipient,)).fetchone()[0]
            row = db.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()
        return self.payload(row), count, existing is None

    @staticmethod
    def payload(row):
        return {"id": row["id"], "from": row["sender"], "ciphertext": row["ciphertext"],
                "timestamp": row["created_at"]}

    def inbox(self, recipient, after=0):
        with self.connect() as db:
            self.prune(db)
            rows = db.execute("SELECT rowid AS cursor,* FROM messages WHERE recipient=? AND state='queued' AND rowid>? ORDER BY rowid LIMIT 500", (recipient, after)).fetchall()
            return [dict(self.payload(row), cursor=row["cursor"]) for row in rows]

    def pending_count(self, recipient):
        # Covered entirely by the small index; no ciphertext is loaded, no queue
        # rows are changed, and expired messages do not inflate the result.
        with self.connect() as db:
            row = db.execute("""SELECT count(*) AS pending_count,coalesce(max(arrival),0) AS revision
                FROM messages INDEXED BY inbox_counts
                WHERE recipient=? AND state='queued' AND expires_at>?""", (recipient, int(time.time()))).fetchone()
            return dict(row)

    def policy(self, owner, contacts, blocked):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            exists = db.execute("SELECT 1 FROM inbox_policy WHERE owner=?", (owner,)).fetchone()
            if not exists and db.execute("SELECT count(*) FROM inbox_policy").fetchone()[0] >= 4096:
                raise OverflowError("Inbox policy capacity reached")
            db.execute("INSERT INTO inbox_policy(owner,contacts,blocked) VALUES (?,?,?) ON CONFLICT(owner) DO UPDATE SET contacts=excluded.contacts,blocked=excluded.blocked",
                       (owner, json.dumps(contacts), json.dumps(blocked)))
            # Blocking retires queued ciphertext without a delivery receipt.
            for peer in blocked:
                db.execute("UPDATE messages SET ciphertext=NULL,state='received',receipt_visible=0 WHERE recipient=? AND sender=? AND state='queued'", (owner, peer))

    def acknowledge(self, recipient, ids, report_delivery=True):
        receipts = []
        acknowledged = 0
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.prune(db)
            for message_id in ids:
                row = db.execute("SELECT sender,state,created_at FROM messages WHERE id=? AND recipient=?", (message_id, recipient)).fetchone()
                if row is None:
                    continue
                quarantined = db.execute("SELECT 1 FROM quarantined_ids WHERE id=?", (message_id,)).fetchone()
                if row["state"] == "queued" or quarantined:
                    acknowledged += 1
                    db.execute("UPDATE messages SET ciphertext=NULL, state='received', receipt_visible=? WHERE id=?",
                               (int(report_delivery), message_id))
                    if report_delivery:
                        receipts.append((row["sender"], message_id))
                    db.execute("DELETE FROM quarantined_ids WHERE id=?", (message_id,))
                    self.statistics.record(db, "messages.acknowledged")
                    delay = max(0, (time.time() - datetime.fromisoformat(row["created_at"]).timestamp()) * 1000)
                    self.statistics.record(db, "messages.ack_delay_ms", delay)
                    if report_delivery:
                        self.statistics.record(db, "messages.delivery_receipts")
        return acknowledged, receipts

    def quarantine(self, recipient, ids):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.prune(db)
            count = 0
            for message_id in ids:
                changed = db.execute("UPDATE messages SET ciphertext=NULL,state='received',receipt_visible=0 WHERE id=? AND recipient=? AND state='queued'", (message_id, recipient)).rowcount
                if changed:
                    db.execute("INSERT OR IGNORE INTO quarantined_ids(id) VALUES (?)", (message_id,))
                    count += 1
                    self.statistics.record(db, "messages.quarantined")
        return count

    def mark_read(self, recipient, ids):
        receipts = []
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.prune(db)
            for message_id in ids:
                row = db.execute("SELECT sender FROM messages WHERE id=? AND recipient=? AND state='received' AND receipt_visible=1 AND viewed=0",
                                 (message_id, recipient)).fetchone()
                if row is not None:
                    db.execute("UPDATE messages SET viewed=1 WHERE id=?", (message_id,))
                    receipts.append((row["sender"], message_id))
        return receipts

    def statuses(self, sender):
        with self.connect() as db:
            self.prune(db)
            rows = db.execute("SELECT id, state, receipt_visible, viewed FROM messages WHERE sender=? ORDER BY rowid LIMIT 500", (sender,)).fetchall()
            return [{"id": row["id"], "state": ("read" if row["viewed"] else row["state"]) if row["receipt_visible"] else "sent"}
                    for row in rows]


def store():
    return current_app.extensions["message_store"]


def add_websocket(user_id, ws):
    with store_lock:
        websocket_connections.setdefault(user_id, []).append(ws)
    record("websocket.opened")


def remove_websocket(user_id, ws):
    removed = False
    with store_lock:
        connections = websocket_connections.get(user_id, [])
        if ws in connections:
            connections.remove(ws)
            removed = True
        if not connections:
            websocket_connections.pop(user_id, None)
    if removed:
        record("websocket.closed")


def send_event(recipient, event):
    with store_lock:
        connections = list(websocket_connections.get(recipient, []))
    handed_to_socket = False
    for ws in connections:
        try:
            if time.monotonic() >= ws.auth_expires_at:
                raise TimeoutError("Session expired")
            ws.send(json.dumps(event))
            handed_to_socket = True
        except Exception:
            remove_websocket(recipient, ws)
    return handed_to_socket


def route_message(sender, recipient, ciphertext, message_id=None):
    try:
        message, queued_count, new = store().enqueue(sender, recipient, ciphertext, message_id)
    except (ValueError, OverflowError) as exc:
        reason = "size" if isinstance(exc, MessageTooLargeError) else "capacity" if isinstance(exc, OverflowError) else "route"
        record(f"messages.rejected.{reason}")
        raise
    handed_to_socket = new and send_event(recipient, {"type": "message", "message": message})
    if handed_to_socket:
        record("messages.socket_handoffs")
    return message, handed_to_socket, queued_count


def acknowledge_messages(recipient, ids, report_delivery=True):
    acknowledged, receipts = store().acknowledge(recipient, ids, report_delivery)
    for sender, message_id in receipts:
        send_event(sender, {"type": "receipt", "id": message_id, "state": "received"})
    return acknowledged
