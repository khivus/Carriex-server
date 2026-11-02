"""Public-exposure regressions through actual localhost HTTP/WebSocket servers."""
import sqlite3
import subprocess
import sys
import json
import time
from pathlib import Path

import pytest
import websocket

from auth_client import authenticate, public_key, remember_challenge, sign, user_id
from conftest import HTTPClient
from test_groups import change, create
from test_prekeys import bundle


def credentials(client, identity):
    return {"Authorization": "Bearer " + authenticate(client, identity)}


def send(client, sender, recipient, headers, content="opaque"):
    return client.post("/send", headers=headers, json=dict(sender=sender, recipient=recipient, ciphertext=content))


def test_accepted_contact_can_queue_more_than_64_messages_and_ack_frees_storage(raw_client):
    sender, recipient = user_id("offline-friend"), user_id("offline-recipient")
    tx, rx = credentials(raw_client, sender), credentials(raw_client, recipient)
    assert raw_client.post(f"/messages/{recipient}/policy", headers=rx,
                           json=dict(contacts=[sender], blocked=[])).status_code == 200
    for _ in range(70):
        response = send(raw_client, sender, recipient, tx)
        assert response.status_code == 201, response.content
    messages = raw_client.get(f"/messages/{recipient}", headers=rx).json()["messages"]
    assert len(messages) == 70
    assert raw_client.post(f"/messages/{recipient}/ack", headers=rx,
                           json=dict(ids=[item["id"] for item in messages])).json()["acknowledged"] == 70
    assert send(raw_client, sender, recipient, tx).status_code == 201


def test_accepting_a_request_immediately_lifts_unknown_sender_limit(raw_client):
    sender, recipient = user_id("request-sender"), user_id("request-recipient")
    tx, rx = credentials(raw_client, sender), credentials(raw_client, recipient)
    raw_client.post(f"/messages/{recipient}/policy", headers=rx, json=dict(contacts=[], blocked=[]))
    assert send(raw_client, sender, recipient, tx).status_code == 201
    assert send(raw_client, sender, recipient, tx).status_code == 201
    assert send(raw_client, sender, recipient, tx).status_code == 429
    raw_client.post(f"/messages/{recipient}/policy", headers=rx, json=dict(contacts=[sender], blocked=[]))
    assert send(raw_client, sender, recipient, tx).status_code == 201


def test_sender_quota_is_fair_and_counters_survive_restart(server_factory):
    running = server_factory(SENDER_PENDING_LIMIT=2)
    client = HTTPClient(running.port)
    sender, other, recipient = [user_id(x) for x in ("quota-sender", "quota-other", "quota-recipient")]
    tx, rx, other_auth = credentials(client, sender), credentials(client, recipient), credentials(client, other)
    first = send(client, sender, recipient, tx).json()["id"]
    assert send(client, sender, recipient, tx).status_code == 201
    assert send(client, sender, recipient, tx).status_code == 429
    assert send(client, other, recipient, other_auth).status_code == 201
    running.stop(); running.start()
    tx, rx = credentials(client, sender), credentials(client, recipient)
    assert send(client, sender, recipient, tx).status_code == 429
    assert client.post(f"/messages/{recipient}/ack", headers=rx, json=dict(ids=[first])).status_code == 200
    assert send(client, sender, recipient, tx).status_code == 201
    with sqlite3.connect(Path(running.config["MESSAGE_DATA_DIR"]) / "messages.sqlite3") as db:
        actual = db.execute("SELECT count(*),sum(state='queued'),sum(coalesce(length(CAST(ciphertext AS BLOB)),0)) FROM messages").fetchone()
        recorded = db.execute("SELECT rows,pending,bytes FROM message_usage WHERE name='all'").fetchone()
    assert actual == recorded


def test_unknown_recipient_cannot_consume_queue_capacity(raw_client):
    sender = user_id("invented-recipient-sender")
    assert send(raw_client, sender, "d" * 64, credentials(raw_client, sender)).status_code == 409


def test_blocked_device_cannot_invite_or_consume_prekeys(raw_client):
    admin, recipient = user_id("blocked-admin"), user_id("blocked-recipient")
    tx, rx = credentials(raw_client, admin), credentials(raw_client, recipient)
    raw_client.post(f"/messages/{recipient}/policy", headers=rx, json=dict(contacts=[], blocked=[admin]))
    state = create(admin)
    assert raw_client.post("/groups/state", headers=tx, json=state).status_code == 200
    assert raw_client.post("/groups/state", headers=tx, json=change(state, admin, "invite", recipient)).status_code == 403
    assert raw_client.post("/prekeys", headers=rx, json=bundle(recipient)).status_code == 200
    assert raw_client.post(f"/prekeys/{recipient}/claim", headers=tx).status_code == 403
    assert raw_client.get("/prekeys/status", headers=rx).json()["available"] == 3


def test_declined_history_does_not_consume_membership_allowance_after_restart(server_factory):
    running = server_factory()
    client = HTTPClient(running.port)
    admin, recipient = user_id("history-admin"), user_id("history-recipient")
    tx, rx = credentials(client, admin), credentials(client, recipient)
    for _ in range(65):
        state = create(admin)
        assert client.post("/groups/state", headers=tx, json=state).status_code == 200
        invitation = change(state, admin, "invite", recipient)
        assert client.post("/groups/state", headers=tx, json=invitation).status_code == 200
        declined = change(invitation, recipient, "decline", recipient)
        assert client.post("/groups/state", headers=rx, json=declined).status_code == 200
        assert client.post("/groups/state", headers=tx, json=change(declined, admin, "close")).status_code == 200
    running.stop(); running.start()
    rx = credentials(client, recipient)
    response = client.post("/groups/state", headers=rx, json=create(recipient))
    assert response.status_code == 200, response.content


def test_pending_invitations_have_a_separate_allowance(server_factory):
    client = HTTPClient(server_factory(GROUP_INVITATION_LIMIT=2).port)
    admin, recipient = user_id("invitation-admin"), user_id("invitation-recipient")
    tx, rx = credentials(client, admin), credentials(client, recipient)
    for index in range(3):
        state = create(admin)
        assert client.post("/groups/state", headers=tx, json=state).status_code == 200
        code = client.post("/groups/state", headers=tx, json=change(state, admin, "invite", recipient)).status_code
        assert code == (200 if index < 2 else 429)
    assert client.post("/groups/state", headers=rx, json=create(recipient)).status_code == 200


def test_prekey_reserve_keeps_keys_for_accepted_contacts(raw_client):
    owner, stranger, friend = [user_id(x) for x in ("reserve-owner", "reserve-stranger", "reserve-friend")]
    rx, unknown, known = credentials(raw_client, owner), credentials(raw_client, stranger), credentials(raw_client, friend)
    raw_client.post(f"/messages/{owner}/policy", headers=rx, json=dict(contacts=[friend], blocked=[]))
    raw_client.post("/prekeys", headers=rx, json=bundle(owner, 12))
    for _ in range(3):
        assert raw_client.post(f"/prekeys/{owner}/claim", headers=unknown).status_code == 200
    assert raw_client.post(f"/prekeys/{owner}/claim", headers=unknown).status_code == 429
    assert raw_client.post(f"/prekeys/{owner}/claim", headers=known).status_code == 200


def test_socket_limit_is_rejected_before_upgrade_and_http_stays_available(server_factory):
    running = server_factory(WS_DEVICE_LIMIT=1, WS_GLOBAL_LIMIT=2)
    client = HTTPClient(running.port)
    owner = user_id("one-socket")
    auth = credentials(client, owner)
    ws = websocket.create_connection(f"ws://127.0.0.1:{running.port}/ws/{owner}", header=auth, timeout=2)
    try:
        with pytest.raises(websocket.WebSocketBadStatusException) as failure:
            websocket.create_connection(f"ws://127.0.0.1:{running.port}/ws/{owner}", header=auth, timeout=2)
        assert failure.value.status_code == 429
        assert client.get("/health").status_code == 200
        assert client.delete("/auth/session", headers=auth).status_code == 200
        assert ws.recv() == ""
        assert client.get(f"/messages/{owner}", headers=auth).status_code == 401
    finally:
        ws.close()


def test_authentication_and_http_rates_are_enforced_without_identity(server_factory):
    client = HTTPClient(server_factory(RATE_LIMIT_ENABLED=True, AUTH_IP_RATE=2).port)
    payload = dict(public_key=public_key(user_id("limited-login")))
    assert client.post("/auth/challenge", json=payload).status_code == 200
    assert client.post("/auth/challenge", json=payload).status_code == 200
    response = client.post("/auth/challenge", json=payload)
    assert response.status_code == 429 and int(response.headers["Retry-After"]) > 0
    client = HTTPClient(server_factory(RATE_LIMIT_ENABLED=True, HTTP_IP_RATE=2).port)
    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 429


def test_health_is_public_but_activity_and_status_cache_are_private(raw_client):
    assert "websocket_clients" not in raw_client.get("/health").json()
    assert raw_client.get("/diagnostics").status_code == 401
    owner = user_id("private-diagnostics")
    auth = credentials(raw_client, owner)
    assert raw_client.get("/diagnostics", headers=auth).status_code == 200
    assert raw_client.get(f"/statuses/{owner}", headers=auth).headers["Cache-Control"] == "no-store"


def test_deep_auth_json_is_rejected_without_server_error(raw_client):
    response = raw_client.post("/auth/challenge", data='[' * 100 + '0' + ']' * 100,
                               headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert raw_client.get("/health").status_code == 200


def test_session_rotation_and_local_admin_revoke_live_credentials(server_factory):
    running = server_factory(AUTH_DEVICE_SESSIONS=2)
    client = HTTPClient(running.port)
    owner = user_id("rotate-owner")
    first, second, third = [credentials(client, owner) for _ in range(3)]
    assert client.get(f"/messages/{owner}", headers=first).status_code == 401
    assert client.get(f"/messages/{owner}", headers=second).status_code == 200
    result = subprocess.run([sys.executable, "-m", "src.admin", "--data-dir", running.config["MESSAGE_DATA_DIR"], "block", owner],
                            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert client.get(f"/messages/{owner}", headers=third).status_code == 401


def test_untrusted_proxy_header_does_not_enable_plaintext_auth(server_factory, monkeypatch):
    monkeypatch.setenv("CARRIEX_TRUST_PROXY", "1")
    monkeypatch.setenv("CARRIEX_PROXY_NETWORKS", "192.0.2.0/24")
    client = HTTPClient(server_factory(ALLOW_INSECURE_HTTP=False, AUTH_ORIGIN="https://chat.example").port)
    assert client.post("/auth/challenge", headers={"X-Forwarded-Proto": "https"},
                       json=dict(public_key=public_key(user_id("spoof-proxy")))).status_code == 426


def test_expired_sessions_do_not_permanently_exhaust_new_device_capacity(server_factory):
    client = HTTPClient(server_factory(AUTH_CAPACITY=2, AUTH_SESSION_TTL=0.1).port)
    credentials(client,user_id("capacity-one"))
    credentials(client,user_id("capacity-two"))
    time.sleep(0.2)
    assert credentials(client,user_id("capacity-three"))


def test_large_inbox_is_paginated_by_bytes_without_losing_messages(raw_client):
    sender, recipient = user_id("large-page-sender"), user_id("large-page-recipient")
    tx, rx = credentials(raw_client,sender), credentials(raw_client,recipient)
    expected = set()
    for _ in range(12):
        expected.add(send(raw_client,sender,recipient,tx,"x"*100000).json()["id"])
    first = raw_client.get(f"/messages/{recipient}",headers=rx)
    assert len(first.content) < 1100000
    assert first.json()["next_cursor"] > 0
    found = {item["id"] for item in first.json()["messages"]}
    later = raw_client.get(f"/messages/{recipient}?after={first.json()['next_cursor']}",headers=rx).json()
    found.update(item["id"] for item in later["messages"])
    assert found == expected


def test_socket_incoming_queue_is_bounded_while_consumer_waits_for_database(server_factory):
    running = server_factory(WS_PENDING_LIMIT=2)
    client = HTTPClient(running.port)
    sender, recipient = user_id("buffer-sender"), user_id("buffer-recipient")
    tx = credentials(client,sender)
    credentials(client,recipient)
    ws = websocket.create_connection(f"ws://127.0.0.1:{running.port}/ws/{sender}",header=tx,timeout=3)
    try:
        with sqlite3.connect(Path(running.config["MESSAGE_DATA_DIR"])/"messages.sqlite3") as db:
            db.execute("BEGIN IMMEDIATE")
            ws.send(json.dumps(dict(type="send",recipient=recipient,ciphertext="opaque")))
            time.sleep(0.1)
            for _ in range(4):
                ws.send(json.dumps(dict(type="health")))
            assert ws.recv() == ""
            db.rollback()
    finally:
        ws.close()
    assert client.get("/health").status_code == 200


def test_private_enrollment_requires_local_approval_and_inactive_directory_cleanup_is_safe(server_factory):
    running = server_factory(REGISTRATION_MODE="approved")
    client = HTTPClient(running.port)
    owner = user_id("approved-owner")
    proof = client.post("/auth/challenge",json=dict(public_key=public_key(owner))).json()
    remember_challenge(proof)
    assert client.post("/auth/verify",json=dict(challenge=proof["challenge"],signature=sign(owner,proof["challenge"]))).status_code == 403
    command = [sys.executable,"-m","src.admin","--data-dir",running.config["MESSAGE_DATA_DIR"]]
    result = subprocess.run(command+["approve",owner],cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=20)
    assert result.returncode == 0, result.stderr
    assert credentials(client,owner)
    database = Path(running.config["MESSAGE_DATA_DIR"])/"messages.sqlite3"
    with sqlite3.connect(database) as db:
        db.execute("UPDATE relay_devices SET last_seen=0 WHERE owner=?",(owner,))
        db.execute("INSERT INTO relay_devices(owner,last_seen) VALUES (?,0)",("e"*64,))
    result = subprocess.run(command+["cleanup"],cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["expired_devices"] == 1
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT approved FROM relay_devices WHERE owner=?",(owner,)).fetchone() == (1,)
        assert db.execute("SELECT 1 FROM relay_devices WHERE owner=?",("e"*64,)).fetchone() is None


def test_public_key_challenge_flood_from_another_source_cannot_lock_out_owner(server_factory,monkeypatch):
    monkeypatch.setenv("CARRIEX_TRUST_PROXY","1")
    monkeypatch.setenv("CARRIEX_PROXY_NETWORKS","127.0.0.1/32")
    client = HTTPClient(server_factory(AUTH_ORIGIN="https://relay.example").port)
    owner = user_id("challenge-flood-owner")
    key = dict(public_key=public_key(owner))
    attacker = {"X-Forwarded-For":"203.0.113.1"}
    for _ in range(3):
        assert client.post("/auth/challenge",headers=attacker,json=key).status_code == 200
    assert client.post("/auth/challenge",headers=attacker,json=key).status_code == 429
    response = client.post("/auth/challenge",headers={"X-Forwarded-For":"203.0.113.2"},json=key)
    assert response.status_code == 200
    proof = response.json(); remember_challenge(proof)
    assert client.post("/auth/verify",json=dict(challenge=proof["challenge"],signature=sign(owner,proof["challenge"]))).status_code == 200
