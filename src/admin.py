"""Local-only device approval, session revocation and storage maintenance."""
import argparse
import json
import os
import sqlite3
from pathlib import Path
import time


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default=os.environ.get("CARRIEX_DATA_DIR", ".carriex-server"))
    parser.add_argument("action", choices=("list", "approve", "block", "unblock", "revoke", "cleanup"))
    parser.add_argument("device", nargs="?")
    args = parser.parse_args(argv)
    directory = Path(args.data_dir).expanduser().resolve()
    if not (directory / "messages.sqlite3").is_file():
        parser.error("No Carriex database exists in this directory")
    from flask import Flask
    from src.security import configure
    app = Flask("carriex-local-admin")
    configure(app)
    from src.auth import valid_user_id
    from src.security_db import cleanup, revoke
    if args.action not in {"list", "cleanup"} and not valid_user_id(args.device):
        parser.error("A 64-character device ID is required")
    with app.app_context(), sqlite3.connect(directory / "messages.sqlite3", timeout=10) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        if args.action == "list":
            print(json.dumps([dict(row) for row in db.execute("SELECT owner,last_seen,approved,revoked FROM relay_devices ORDER BY owner")], indent=2))
        elif args.action == "cleanup":
            db.execute("DELETE FROM messages WHERE expires_at<=?", (time.time(),))
            db.execute("DELETE FROM quarantined_ids WHERE NOT EXISTS (SELECT 1 FROM messages WHERE messages.id=quarantined_ids.id)")
            devices, groups = cleanup(db, int(os.environ.get("CARRIEX_MESSAGE_TTL_SECONDS", 30 * 86400)))
            print(json.dumps(dict(expired_devices=devices, expired_closed_groups=groups)))
        elif args.action in {"block", "revoke"}:
            revoke(db, args.device, blocked=args.action == "block")
            print("Device blocked and sessions revoked" if args.action == "block" else "Device sessions revoked")
        elif args.action == "approve":
            db.execute("INSERT INTO relay_devices(owner,last_seen,approved) VALUES (?,?,1) ON CONFLICT(owner) DO UPDATE SET approved=1",
                       (args.device, time.time()))
            print("Device approved")
        elif args.action == "unblock":
            db.execute("UPDATE relay_devices SET revoked=0,version=version+1 WHERE owner=?", (args.device,))
            print("Device unblocked; a fresh authentication proof is required")


if __name__ == "__main__":
    main()
