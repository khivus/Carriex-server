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


websocket_connections = {}
store_lock = Lock()


class MessageStore:
    def __init__(self, path, ttl_seconds=30 * 24 * 3600):
        self.path = str(path)
        self.ttl_seconds = int(ttl_seconds)
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
            db.execute("CREATE INDEX IF NOT EXISTS inbox ON messages(recipient, state, expires_at)")
            db.execute("CREATE INDEX IF NOT EXISTS outbox ON messages(sender, expires_at)")

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
        db.execute("DELETE FROM messages WHERE expires_at <= ?", (int(time.time()),))

    def enqueue(self, sender, recipient, ciphertext, message_id=None):
        message_id = message_id or uuid.uuid4().hex
        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.prune(db)
            existing = db.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()
            if existing:
                if (existing["sender"], existing["recipient"]) != (sender, recipient):
                    raise ValueError("Message ID already belongs to another route")
                if existing["ciphertext"] is not None and existing["ciphertext"] != ciphertext:
                    raise ValueError("Message ID already has different content")
            else:
                count = db.execute("SELECT count(*) FROM messages WHERE recipient=? AND state='queued'", (recipient,)).fetchone()[0]
                if count >= 1000:
                    raise OverflowError("Recipient queue is full")
                db.execute("INSERT INTO messages(id,sender,recipient,ciphertext,created_at,expires_at,state) VALUES (?,?,?,?,?,?,?)", (
                    message_id, sender, recipient, ciphertext,
                    datetime.now(timezone.utc).isoformat(), now + self.ttl_seconds, "queued",
                ))
            count = db.execute("SELECT count(*) FROM messages WHERE recipient=? AND state='queued'", (recipient,)).fetchone()[0]
            row = db.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()
        return self.payload(row), count, existing is None

    @staticmethod
    def payload(row):
        return {"id": row["id"], "from": row["sender"], "ciphertext": row["ciphertext"],
                "timestamp": row["created_at"]}

    def inbox(self, recipient):
        with self.connect() as db:
            self.prune(db)
            rows = db.execute("SELECT * FROM messages WHERE recipient=? AND state='queued' ORDER BY rowid LIMIT 500", (recipient,)).fetchall()
            return [self.payload(row) for row in rows]

    def acknowledge(self, recipient, ids, report_delivery=True):
        receipts = []
        acknowledged = 0
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.prune(db)
            for message_id in ids:
                row = db.execute("SELECT sender, state FROM messages WHERE id=? AND recipient=?", (message_id, recipient)).fetchone()
                if row is None:
                    continue
                if row["state"] == "queued":
                    acknowledged += 1
                    db.execute("UPDATE messages SET ciphertext=NULL, state='received', receipt_visible=? WHERE id=?",
                               (int(report_delivery), message_id))
                    if report_delivery:
                        receipts.append((row["sender"], message_id))
        return acknowledged, receipts

    def statuses(self, sender):
        with self.connect() as db:
            self.prune(db)
            rows = db.execute("SELECT id, state, receipt_visible FROM messages WHERE sender=? ORDER BY rowid LIMIT 500", (sender,)).fetchall()
            return [{"id": row["id"], "state": row["state"] if row["receipt_visible"] else "sent"}
                    for row in rows]


def store():
    return current_app.extensions["message_store"]


def add_websocket(user_id, ws):
    with store_lock:
        websocket_connections.setdefault(user_id, []).append(ws)


def remove_websocket(user_id, ws):
    with store_lock:
        connections = websocket_connections.get(user_id, [])
        if ws in connections:
            connections.remove(ws)
        if not connections:
            websocket_connections.pop(user_id, None)


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
    message, queued_count, new = store().enqueue(sender, recipient, ciphertext, message_id)
    handed_to_socket = new and send_event(recipient, {"type": "message", "message": message})
    return message, handed_to_socket, queued_count


def acknowledge_messages(recipient, ids, report_delivery=True):
    acknowledged, receipts = store().acknowledge(recipient, ids, report_delivery)
    for sender, message_id in receipts:
        send_event(sender, {"type": "receipt", "id": message_id, "state": "received"})
    return acknowledged
