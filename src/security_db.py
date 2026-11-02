"""Durable enrollment, revocation and fair-use counters; no private client keys."""
import hashlib
import time

from flask import current_app, request


def initialize(db):
    fresh = db.execute("SELECT 1 FROM sqlite_master WHERE name='relay_devices'").fetchone() is None
    db.execute("""CREATE TABLE IF NOT EXISTS relay_devices (
        owner TEXT PRIMARY KEY,last_seen REAL NOT NULL,approved INTEGER NOT NULL DEFAULT 0,
        revoked INTEGER NOT NULL DEFAULT 0,version INTEGER NOT NULL DEFAULT 0)""")
    db.execute("CREATE INDEX IF NOT EXISTS device_idle ON relay_devices(last_seen)")
    db.execute("""CREATE TABLE IF NOT EXISTS security_budgets (
        name TEXT PRIMARY KEY,window INTEGER NOT NULL,used INTEGER NOT NULL,expires REAL NOT NULL)""")
    db.execute("CREATE INDEX IF NOT EXISTS budget_expiry ON security_budgets(expires)")
    db.execute("CREATE TABLE IF NOT EXISTS resource_activity (kind TEXT NOT NULL,owner TEXT NOT NULL,updated REAL NOT NULL,PRIMARY KEY(kind,owner))")
    if fresh:
        now = time.time()
        # Existing publication/policy/sender records were created by authenticated
        # owners. Invented message recipients are deliberately not enrolled.
        for table, field in (("prekey_bundles", "owner"), ("inbox_policy", "owner"), ("messages", "sender")):
            if db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone():
                db.execute(f"INSERT OR IGNORE INTO relay_devices(owner,last_seen) SELECT DISTINCT {field},? FROM {table}", (now,))


def durable_budget(db, name, maximum, period=3600, amount=1):
    if not current_app.config["RATE_LIMIT_ENABLED"]:
        return True
    now = time.time()
    window = int(now // period)
    db.execute("DELETE FROM security_budgets WHERE expires<=?", (now,))
    row = db.execute("SELECT window,used FROM security_budgets WHERE name=?", (name,)).fetchone()
    used = row[1] if row and row[0] == window else 0
    if used + amount > maximum:
        return False
    if row is None and db.execute("SELECT count(*) FROM security_budgets").fetchone()[0] >= 20000:
        return False
    db.execute("INSERT INTO security_budgets VALUES (?,?,?,?) ON CONFLICT(name) DO UPDATE SET window=excluded.window,used=excluded.used,expires=excluded.expires",
               (name, window, used + amount, (window + 1) * period))
    return True


def activity(db, kind, owner):
    db.execute("INSERT INTO resource_activity VALUES (?,?,?) ON CONFLICT(kind,owner) DO UPDATE SET updated=excluded.updated",
               (kind, owner, time.time()))


def enroll(owner):
    from src.store import store
    with store().connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM relay_devices WHERE owner=?", (owner,)).fetchone()
        if row and row["revoked"]:
            return None, ("Device access has been revoked", 403)
        if current_app.config["REGISTRATION_MODE"] == "approved" and (row is None or not row["approved"]):
            return None, ("This device needs approval from the server owner", 403)
        if row is None:
            cleanup(db, store().ttl_seconds)
            if db.execute("SELECT count(*) FROM relay_devices").fetchone()[0] >= current_app.config.get("DEVICE_OWNER_LIMIT", 4096):
                return None, ("Device directory capacity reached; contact the server owner", 429)
            # Hash the source in durable counters; do not retain raw IP addresses.
            source = hashlib.sha256((request.remote_addr or "unknown").encode()).hexdigest()
            db.execute("SAVEPOINT enrollment_budget")
            if not durable_budget(db, "enroll:source:" + source, current_app.config["ENROLL_IP_HOURLY"]) or not durable_budget(
                db, "enroll:all", current_app.config["ENROLL_GLOBAL_HOURLY"]
            ):
                db.execute("ROLLBACK TO enrollment_budget")
                db.execute("RELEASE enrollment_budget")
                return None, ("New-device enrollment is busy; retry later", 429)
            db.execute("RELEASE enrollment_budget")
            db.execute("INSERT INTO relay_devices(owner,last_seen) VALUES (?,?)", (owner, time.time()))
            return 0, None
        db.execute("UPDATE relay_devices SET last_seen=? WHERE owner=?", (time.time(), owner))
        return row["version"], None


def allowed(owner, version=None):
    from src.store import store
    with store().connect() as db:
        row = db.execute("SELECT revoked,version FROM relay_devices WHERE owner=?", (owner,)).fetchone()
    return row is not None and not row[0] and (version is None or row[1] == version)


def cleanup(db, ttl):
    """Expire inactive directories; retain active signed chains and deny records."""
    cutoff = time.time() - max(current_app.config["DIRECTORY_IDLE_DAYS"] * 86400, ttl)
    stale = db.execute("SELECT owner FROM relay_devices WHERE last_seen<? AND approved=0 AND revoked=0", (cutoff,)).fetchall()
    deleted = 0
    for row in stale:
        owner = row[0]
        if db.execute("SELECT 1 FROM messages WHERE (sender=? OR recipient=?) AND state='queued' AND expires_at>? LIMIT 1", (owner, owner, time.time())).fetchone():
            continue
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='group_access'").fetchone() and db.execute(
            "SELECT 1 FROM group_access WHERE owner=? AND invited=0 AND last_revision IS NULL LIMIT 1", (owner,)
        ).fetchone():
            continue
        for table in ("inbox_policy", "prekey_bundles", "one_time_prekeys", "notification_tokens"):
            if db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone():
                db.execute(f"DELETE FROM {table} WHERE owner=?", (owner,))
        db.execute("DELETE FROM relay_devices WHERE owner=?", (owner,))
        deleted += 1
    closed = db.execute("SELECT owner FROM resource_activity WHERE kind='closed-group' AND updated<?", (cutoff,)).fetchall()
    for row in closed:
        for table in ("group_access", "group_events", "group_periods", "group_admissions", "group_keys", "group_messages", "group_deliveries"):
            db.execute(f"DELETE FROM {table} WHERE group_id=?", (row[0],))
        db.execute("DELETE FROM groups WHERE id=?", (row[0],))
        db.execute("DELETE FROM resource_activity WHERE kind='closed-group' AND owner=?", (row[0],))
    db.execute("DELETE FROM security_budgets WHERE expires<=?", (time.time(),))
    return deleted, len(closed)


def revoke(db, owner, blocked=False):
    db.execute("INSERT INTO relay_devices(owner,last_seen,revoked,version) VALUES (?,?,?,1) ON CONFLICT(owner) DO UPDATE SET version=version+1,revoked=max(revoked,excluded.revoked)",
               (owner, time.time(), int(blocked)))
    if db.execute("SELECT 1 FROM sqlite_master WHERE name='notification_tokens'").fetchone():
        db.execute("DELETE FROM notification_tokens WHERE owner=?", (owner,))
