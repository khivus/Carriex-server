"""Optional persistent relay measurements and a read-only localhost viewer.

python -m src.statistics show
python -m src.statistics serve --port 8766
python -m src.statistics export --format csv --output experiment.csv
"""
import argparse
import csv
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import sqlite3
import time
from urllib.parse import urlsplit

from flask import current_app, g, request


def enabled_value(value):
    if value in (True, 1, "1", "true", "yes", "on"):
        return True
    if value in (False, 0, "0", "false", "no", "off", ""):
        return False
    raise ValueError("CARRIEX_STATISTICS must be 0 or 1")


def retention_days(value):
    days = int(value)
    if not 1 <= days <= 365:
        raise ValueError("CARRIEX_STATISTICS_RETENTION_DAYS must be between 1 and 365")
    return days


class RelayStatistics:
    """Hourly aggregates only: no IDs, addresses, bodies, keys, or raw requests."""
    def __init__(self, enabled=False, days=30):
        self.enabled = enabled
        self.days = retention_days(days)

    def initialize(self, db):
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE name='statistics_meta'").fetchone()
        if not self.enabled and not exists:
            return
        db.execute("CREATE TABLE IF NOT EXISTS statistics_meta (name TEXT PRIMARY KEY,value TEXT NOT NULL)")
        db.execute("""CREATE TABLE IF NOT EXISTS statistics_hourly (
            hour INTEGER NOT NULL,metric TEXT NOT NULL,samples INTEGER NOT NULL,
            total REAL NOT NULL,minimum REAL NOT NULL,maximum REAL NOT NULL,
            PRIMARY KEY(hour,metric))""")
        for name, value in (("enabled", int(self.enabled)), ("retention_days", self.days)):
            db.execute("INSERT INTO statistics_meta VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                       (name, str(value)))
        db.execute("DELETE FROM statistics_hourly WHERE hour<?", (int(time.time()) - self.days * 86400,))

    def record(self, db, metric, value=1, samples=1):
        if not self.enabled or samples <= 0:
            return
        hour = int(time.time()) // 3600 * 3600
        db.execute("""INSERT INTO statistics_hourly VALUES (?,?,?,?,?,?)
            ON CONFLICT(hour,metric) DO UPDATE SET samples=samples+excluded.samples,
            total=total+excluded.total,minimum=min(minimum,excluded.minimum),
            maximum=max(maximum,excluded.maximum)""", (hour, metric, samples, value, value / samples, value / samples))
        db.execute("DELETE FROM statistics_hourly WHERE hour<?", (hour - self.days * 86400,))


def record(metric, value=1):
    """For observations outside a message transaction, including WebSocket events."""
    message_store = current_app.extensions["message_store"]
    if message_store.statistics.enabled:
        try:
            with message_store.connect() as db:
                message_store.statistics.record(db, metric, value)
        except sqlite3.Error:
            current_app.logger.warning("Unable to save relay statistics")


def register_statistics(app):
    @app.before_request
    def start_measurement():
        g.statistics_started = time.perf_counter()

    @app.after_request
    def finish_measurement(response):
        if hasattr(g, "statistics_started") and not request.environ.get("wsgi.websocket") and not request.path.startswith("/ws/"):
            # Endpoint names come from the route registry, never from a URL/ID.
            endpoint = request.endpoint or "unknown"
            method = request.method if request.method in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} else "OTHER"
            record(f"http.{method}.{endpoint}.{response.status_code // 100}xx_ms",
                   (time.perf_counter() - g.statistics_started) * 1000)
        return response


def snapshot(path, days=30):
    days = retention_days(days)
    path = Path(path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Relay database does not exist: {path}. Start the relay first.")
    # Read-only connections cannot initialize, reset, or alter the relay database.
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE name='statistics_hourly'").fetchone()
        meta = dict(db.execute("SELECT name,value FROM statistics_meta")) if exists else {}
        rows = db.execute("SELECT * FROM statistics_hourly WHERE hour>=? ORDER BY hour,metric",
                          (int(time.time()) // 3600 * 3600 - days * 86400,)).fetchall() if exists else []
        queue = dict(db.execute("""SELECT count(*) AS messages,
            coalesce(sum(length(CAST(ciphertext AS BLOB))),0) AS bytes
            FROM messages WHERE state='queued' AND expires_at>?""", (int(time.time()),)).fetchone())
        prekeys = db.execute("SELECT 1 FROM sqlite_master WHERE name='one_time_prekeys'").fetchone()
        queue["available_prekeys"] = db.execute("SELECT count(*) FROM one_time_prekeys WHERE expires_at>? AND claimed=0",
                                               (int(time.time()),)).fetchone()[0] if prekeys else 0
    totals = {}
    hourly = []
    for row in rows:
        item = dict(row)
        item["utc"] = datetime.fromtimestamp(item["hour"], timezone.utc).isoformat()
        item["mean"] = item["total"] / item["samples"]
        hourly.append(item)
        total = totals.setdefault(item["metric"], dict(samples=0, total=0, minimum=item["minimum"], maximum=item["maximum"]))
        total["samples"] += item["samples"]
        total["total"] += item["total"]
        total["minimum"] = min(total["minimum"], item["minimum"])
        total["maximum"] = max(total["maximum"], item["maximum"])
    for item in totals.values():
        item["mean"] = item["total"] / item["samples"]
    return dict(generated_at=datetime.now(timezone.utc).isoformat(), days=days,
                collection_enabled=meta.get("enabled") == "1", retention_days=int(meta.get("retention_days", 30)),
                queue=queue, metrics=totals, hourly=hourly,
                definitions={"messages.size_bytes": "UTF-8 bytes of the opaque relay ciphertext field (hex on current Android clients)",
                             "messages.ack_delay_ms": "Relay acceptance to first recipient acknowledgement; includes offline time, polling and client processing; not read time",
                             "http.*_ms": "Server HTTP handling time, excluding network transit and response transfer",
                             "prekeys.claimed": "One-time public prekeys claimed, not necessarily used to establish a session"})


def export_csv(data):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=["utc", "hour", "metric", "samples", "total", "minimum", "maximum", "mean"])
    writer.writeheader()
    writer.writerows(data["hourly"])
    return output.getvalue()


def viewer(path, port=8766, days=30):
    from src.statistics_ui import PAGE

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Reject cross-site/DNS-rebinding access to this local data viewer.
            if self.headers.get("Host") not in {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}:
                self.send_error(403)
                return
            route = urlsplit(self.path).path
            if route == "/":
                body, content_type = PAGE, "text/html; charset=utf-8"
            elif route in {"/api/statistics", "/export.json", "/export.csv"}:
                try:
                    data = snapshot(path, days)
                except (OSError, sqlite3.Error):
                    self.send_error(503, "Relay statistics are temporarily unavailable")
                    return
                body, content_type = ((export_csv(data), "text/csv; charset=utf-8") if route.endswith(".csv")
                                      else (json.dumps(data, indent=2), "application/json"))
            else:
                self.send_error(404)
                return
            encoded = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main(argv=None):
    from src.config import read_config
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=".env")
    parser.add_argument("--data-dir", help="Same private data directory as the relay")
    parser.add_argument("--days", type=int, default=30)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("show", help="Print saved aggregates and the current queue")
    serve = commands.add_parser("serve", help="Read-only dashboard at http://127.0.0.1:8766")
    serve.add_argument("--port", type=int, default=8766)
    export = commands.add_parser("export", help="Export saved measurements")
    export.add_argument("--format", choices=["json", "csv"], default="json")
    export.add_argument("--output", help="Write a file instead of stdout")
    args = parser.parse_args(argv)
    try:
        config = read_config(args.config)
        directory = Path(args.data_dir or os.environ.get("CARRIEX_DATA_DIR") or config.get("CARRIEX_IDENTITY_DIR") or ".carriex-server")
        path = directory / "messages.sqlite3"
        data = snapshot(path, args.days)
        if args.command == "serve":
            if not 1 <= args.port <= 65535:
                raise ValueError("Dashboard port must be between 1 and 65535")
            with viewer(path, args.port, args.days) as server:
                print(f"Statistics dashboard: http://127.0.0.1:{server.server_port}\nDatabase: {path.resolve()}", flush=True)
                server.serve_forever()
        elif args.command == "export":
            text = export_csv(data) if args.format == "csv" else json.dumps(data, indent=2) + "\n"
            if args.output:
                Path(args.output).write_text(text, encoding="utf-8")
            else:
                print(text, end="")
        else:
            print(f"Collection configured: {'enabled' if data['collection_enabled'] else 'disabled'}; window: {args.days} days")
            print(f"Queue: {data['queue']['messages']} messages, {data['queue']['bytes']} bytes; available OPKs: {data['queue']['available_prekeys']}")
            for name, value in sorted(data["metrics"].items()):
                print(f"{name}: total={value['total']:.3f}, samples={value['samples']}, mean={value['mean']:.3f}, min={value['minimum']:.3f}, max={value['maximum']:.3f}")
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f"Unable to read statistics: {exc}\n")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
