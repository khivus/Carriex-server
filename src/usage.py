"""SQLite-maintained queue usage avoids rescanning ciphertext on every send."""


def initialize(db):
    fresh = db.execute("SELECT 1 FROM sqlite_master WHERE name='message_usage'").fetchone() is None
    db.execute("CREATE TABLE IF NOT EXISTS message_usage (name TEXT PRIMARY KEY,rows INTEGER NOT NULL,pending INTEGER NOT NULL,bytes INTEGER NOT NULL)")
    if fresh:
        for name, grouping in (("'all'", ""), ("'sender:' || sender", "GROUP BY sender"), ("'recipient:' || recipient", "GROUP BY recipient")):
            db.execute(f"INSERT INTO message_usage SELECT {name},count(*),coalesce(sum(state='queued'),0),coalesce(sum(length(CAST(ciphertext AS BLOB))),0) FROM messages {grouping}")
    for event in ("INSERT", "UPDATE", "DELETE"):
        statements = []
        for prefix, column in (("all", None), ("sender:", "sender"), ("recipient:", "recipient")):
            new_name = f"'{prefix}'" + (f" || NEW.{column}" if column else "")
            old_name = f"'{prefix}'" + (f" || OLD.{column}" if column else "")
            if event in {"DELETE", "UPDATE"}:
                statements.append(f"UPDATE message_usage SET rows=rows-1,pending=pending-(OLD.state='queued'),bytes=bytes-coalesce(length(CAST(OLD.ciphertext AS BLOB)),0) WHERE name={old_name};")
            if event in {"INSERT", "UPDATE"}:
                statements.append(f"INSERT INTO message_usage VALUES ({new_name},1,NEW.state='queued',coalesce(length(CAST(NEW.ciphertext AS BLOB)),0)) ON CONFLICT(name) DO UPDATE SET rows=rows+1,pending=pending+excluded.pending,bytes=bytes+excluded.bytes;")
        db.execute(f"CREATE TRIGGER IF NOT EXISTS queue_usage_{event.lower()} AFTER {event} ON messages BEGIN " + " ".join(statements) + " END")


def usage(db, name):
    row = db.execute("SELECT rows,pending,bytes FROM message_usage WHERE name=?", (name,)).fetchone()
    return tuple(row) if row else (0, 0, 0)


def initialize_groups(db):
    db.execute("CREATE TABLE IF NOT EXISTS object_usage (kind TEXT NOT NULL,owner TEXT NOT NULL,rows INTEGER NOT NULL,bytes INTEGER NOT NULL,PRIMARY KEY(kind,owner))")
    for table, payload, actor in (("group_events", "body", "json_extract({row}.body,'$.admin')"),
                                  ("group_keys", "wire", "{row}.sender"),
                                  ("group_messages", "wire", "{row}.sender")):
        if db.execute("SELECT 1 FROM object_usage WHERE kind=? AND owner=''", (table,)).fetchone() is None:
            db.execute(f"INSERT INTO object_usage SELECT ?, '',count(*),coalesce(sum(length({payload})),0) FROM {table}", (table,))
            db.execute(f"INSERT INTO object_usage SELECT ?,{actor.format(row=table)},count(*),sum(length({payload})) FROM {table} GROUP BY {actor.format(row=table)}", (table,))
        for event in ("INSERT", "UPDATE", "DELETE"):
            commands = []
            for expression in ("''", actor):
                if event in {"UPDATE", "DELETE"}:
                    owner = expression.format(row="OLD")
                    commands.append(f"UPDATE object_usage SET rows=rows-1,bytes=bytes-length(OLD.{payload}) WHERE kind='{table}' AND owner={owner};")
                if event in {"UPDATE", "INSERT"}:
                    owner = expression.format(row="NEW")
                    commands.append(f"INSERT INTO object_usage VALUES ('{table}',{owner},1,length(NEW.{payload})) ON CONFLICT(kind,owner) DO UPDATE SET rows=rows+1,bytes=bytes+excluded.bytes;")
            db.execute(f"CREATE TRIGGER IF NOT EXISTS usage_{table}_{event.lower()} AFTER {event} ON {table} BEGIN " + " ".join(commands) + " END")


def object_usage(db, kind, owner=""):
    row = db.execute("SELECT rows,bytes FROM object_usage WHERE kind=? AND owner=?", (kind, owner)).fetchone()
    return tuple(row) if row else (0, 0)
