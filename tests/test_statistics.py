"""Live HTTP collection, restart persistence, and shipped CLI/viewer integration."""
import csv
import io
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time

from auth_client import user_id
from conftest import HTTPClient
from test_prekeys import bundle, headers

ROOT = Path(__file__).resolve().parents[1]


def cli(directory, *args):
    result = subprocess.run([sys.executable, "-m", "src.statistics", "--config", str(directory / "absent.env"),
                             "--data-dir", str(directory), *args], cwd=ROOT, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return result.stdout


def total(data, name):
    return data["metrics"].get(name, {}).get("total", 0)


def test_collection_counts_unique_delivery_and_prekeys_and_survives_restart(server_factory, tmp_path):
    directory = tmp_path / "relay"
    running = server_factory(MESSAGE_DATA_DIR=str(directory), STATISTICS_ENABLED=True)
    client = HTTPClient(running.port)
    sender, recipient = user_id("statistics-sender"), user_id("statistics-recipient")
    sending, receiving = headers(client, sender), headers(client, recipient)
    message = dict(id="a" * 32, sender=sender, recipient=recipient, ciphertext="opaque-experiment-content")
    for _ in range(2):
        assert client.post("/send", headers=sending, json=message).status_code == 201
    for expected in (1, 0):
        assert client.post(f"/messages/{recipient}/ack", headers=receiving,
                           json=dict(ids=[message["id"]])).json()["acknowledged"] == expected
    upload = bundle(recipient, 2)
    assert client.post("/prekeys", headers=receiving, json=upload).status_code == 200
    for _ in range(3):
        assert client.post(f"/prekeys/{recipient}/claim", headers=sending, json={}).status_code == 200
    assert client.post("/send", json=message).status_code == 401
    assert client.post("/send", headers=sending, json={**message, "id": "b" * 32,
                       "ciphertext": "x" * (256 * 1024 + 1)}).status_code == 413
    data = json.loads(cli(directory, "export"))
    expected = {"messages.accepted": 1, "messages.duplicate_submissions": 1, "messages.acknowledged": 1,
                "messages.delivery_receipts": 1, "messages.size_bytes": len(message["ciphertext"]),
                "messages.rejected.size": 1, "prekeys.published": 2, "prekeys.claimed": 2,
                "prekeys.claims_without_opk": 1}
    assert data["collection_enabled"]
    for metric, value in expected.items():
        assert total(data, metric) == value, metric
    assert data["metrics"]["messages.ack_delay_ms"]["samples"] == 1
    assert data["metrics"]["messages.ack_delay_ms"]["mean"] >= 0
    assert data["metrics"]["http.POST.api.send_message.4xx_ms"]["samples"] == 2
    for private in (sender, recipient, message["id"], message["ciphertext"], upload["identity_key"], sending["Authorization"]):
        assert private not in json.dumps(data)
    rows = list(csv.DictReader(io.StringIO(cli(directory, "export", "--format", "csv"))))
    assert any(row["metric"] == "messages.accepted" and float(row["total"]) == 1 for row in rows)
    running.stop()
    restarted = server_factory(MESSAGE_DATA_DIR=str(directory), STATISTICS_ENABLED=True)
    assert HTTPClient(restarted.port).get("/health").status_code == 200
    assert total(json.loads(cli(directory, "export")), "messages.accepted") == 1
    assert HTTPClient(restarted.port).get("/statistics").status_code == 404


def test_disabled_collection_creates_no_tables(server_factory, tmp_path):
    directory = tmp_path / "disabled"
    running = server_factory(MESSAGE_DATA_DIR=str(directory), STATISTICS_ENABLED=False)
    assert HTTPClient(running.port).get("/health").status_code == 200
    data = json.loads(cli(directory, "export"))
    assert not data["collection_enabled"] and not data["metrics"]
    with sqlite3.connect(directory / "messages.sqlite3") as db:
        assert not db.execute("SELECT name FROM sqlite_master WHERE name LIKE 'statistics_%'").fetchall()


def test_quarantine_expiry_and_retention_are_separate_from_delivery(server_factory, tmp_path):
    directory = tmp_path / "short-lived"
    running = server_factory(MESSAGE_DATA_DIR=str(directory), STATISTICS_ENABLED=True, MESSAGE_TTL_SECONDS=1,
                             STATISTICS_RETENTION_DAYS=1)
    client = HTTPClient(running.port)
    sender, recipient = user_id("stats-quarantine-sender"), user_id("stats-quarantine-recipient")
    sending, receiving = headers(client, sender), headers(client, recipient)
    for mid in ("c" * 32, "d" * 32):
        assert client.post("/send", headers=sending, json=dict(id=mid, sender=sender, recipient=recipient, ciphertext="opaque")).status_code == 201
    assert client.post(f"/messages/{recipient}/ack", headers=receiving,
                       json=dict(ids=["c" * 32], quarantine=True)).status_code == 200
    with sqlite3.connect(directory / "messages.sqlite3") as db:
        db.execute("INSERT INTO statistics_hourly VALUES (0,'old-test-counter',1,1,1,1)")
    time.sleep(1.1)
    assert client.get(f"/messages/{recipient}", headers=receiving).json()["messages"] == []
    data = json.loads(cli(directory, "export"))
    assert total(data, "messages.quarantined") == 1
    assert total(data, "messages.expired") == 1
    assert total(data, "messages.acknowledged") == 0
    with sqlite3.connect(directory / "messages.sqlite3") as db:
        assert not db.execute("SELECT 1 FROM statistics_hourly WHERE hour=0").fetchone()


def test_local_viewer_exports_and_rejects_foreign_hosts(server_factory, tmp_path):
    directory = tmp_path / "viewer"
    server_factory(MESSAGE_DATA_DIR=str(directory), STATISTICS_ENABLED=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    command = [sys.executable, "-m", "src.statistics", "--config", str(tmp_path / "absent.env"),
               "--data-dir", str(directory), "serve", "--port", str(port)]
    with (tmp_path / "viewer.log").open("w") as log:
        process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=log)
        try:
            client = HTTPClient(port)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    page = client.get("/")
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError((tmp_path / "viewer.log").read_text())
            assert page.status_code == 200 and b"Relay statistics" in page.content
            assert client.get("/api/statistics").json()["collection_enabled"]
            assert client.get("/export.csv").content.startswith(b"utc,hour,metric")
            assert client.get("/", headers={"Host": "untrusted.example"}).status_code == 403
            assert client.get("/server-key.pem").status_code == 404
        finally:
            process.terminate()
            process.wait(timeout=10)
