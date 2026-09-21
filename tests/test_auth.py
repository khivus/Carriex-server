"""Authentication attacks and lifecycle tests against real localhost servers."""
import base64
import concurrent.futures
import json
import time

import pytest
import websocket

from auth_client import authenticate, public_key, remember_challenge, sign, user_id
from conftest import HTTPClient


def headers(token):
    return {"Authorization": "Bearer " + token}


def challenge(client, identity):
    response = client.post("/auth/challenge", json={"public_key": public_key(identity)})
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    return remember_challenge(response.json())


@pytest.mark.parametrize("path,method", [("/send", "POST"), ("/messages/" + "a" * 64, "GET")])
def test_http_requires_authentication(raw_client, path, method):
    assert raw_client.request(method, path).status_code == 401


def test_websocket_rejected_before_upgrade(server_port):
    with pytest.raises(websocket.WebSocketBadStatusException) as failure:
        websocket.create_connection(f"ws://127.0.0.1:{server_port}/ws/{'a' * 64}", timeout=2)
    assert failure.value.status_code == 401


@pytest.mark.parametrize("value", [None, "", "invalid", "A" * 1000, [], {}, 123])
def test_malformed_public_key(raw_client, value):
    assert raw_client.post("/auth/challenge", json={"public_key": value}).status_code == 400


def test_registration_and_repeat_login_are_same_identity(raw_client):
    identity = user_id("device")
    first = authenticate(raw_client, identity)
    second = authenticate(raw_client, identity)
    assert first != second
    for token in (first, second):
        response = raw_client.get("/messages/" + identity, headers=headers(token))
        assert response.status_code == 200
        assert response.json()["messages"] == []


def test_wrong_key_cannot_claim_identity(raw_client):
    victim, attacker = user_id("victim"), user_id("attacker")
    nonce = challenge(raw_client, victim)
    response = raw_client.post("/auth/verify", json={
        "challenge": nonce, "signature": sign(attacker, nonce, victim),
    })
    assert response.status_code == 401
    # Failed proofs consume their challenge as well.
    assert raw_client.post("/auth/verify", json={
        "challenge": nonce, "signature": sign(victim, nonce),
    }).status_code == 401
    assert authenticate(raw_client, victim)


def test_challenge_replay_is_rejected(raw_client):
    identity = user_id("device")
    nonce = challenge(raw_client, identity)
    proof = {"challenge": nonce, "signature": sign(identity, nonce)}
    assert raw_client.post("/auth/verify", json=proof).status_code == 200
    assert raw_client.post("/auth/verify", json=proof).status_code == 401


def test_concurrent_replay_issues_only_one_session(raw_client):
    identity = user_id("device")
    nonce = challenge(raw_client, identity)
    proof = {"challenge": nonce, "signature": sign(identity, nonce)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        codes = list(pool.map(lambda _: raw_client.post("/auth/verify", json=proof).status_code, range(4)))
    assert sorted(codes) == [200, 401, 401, 401]


def test_proof_for_different_challenge_fails(raw_client):
    identity = user_id("device")
    first, second = challenge(raw_client, identity), challenge(raw_client, identity)
    assert raw_client.post("/auth/verify", json={
        "challenge": second, "signature": sign(identity, first),
    }).status_code == 401


@pytest.mark.parametrize("signature", ["!", base64.b64encode(b"bad signature").decode(), None, []])
def test_invalid_signature_encoding(raw_client, signature):
    nonce = challenge(raw_client, user_id("device"))
    assert raw_client.post("/auth/verify", json={"challenge": nonce, "signature": signature}).status_code == 401


def test_sender_spoofing_and_inbox_theft_rejected(raw_client):
    alice, bob = user_id("alice"), user_id("bob")
    token = authenticate(raw_client, alice)
    assert raw_client.post("/send", json={
        "sender": bob, "recipient": alice, "ciphertext": "spoofed",
    }, headers=headers(token)).status_code == 403
    assert raw_client.get("/messages/" + bob, headers=headers(token)).status_code == 403
    assert raw_client.get("/messages/" + alice, headers=headers(token)).json()["messages"] == []


def test_websocket_cannot_subscribe_as_another_device(raw_client, server_port):
    token = authenticate(raw_client, user_id("alice"))
    with pytest.raises(websocket.WebSocketBadStatusException) as failure:
        websocket.create_connection(f"ws://127.0.0.1:{server_port}/ws/{user_id('bob')}",
                                    header=headers(token), timeout=2)
    assert failure.value.status_code == 403
    assert raw_client.get("/health").json()["websocket_clients"] == 0


def test_websocket_sender_is_verified(websocket, receive_json, client):
    alice, bob = user_id("alice"), user_id("bob")
    ws = websocket(alice)
    ws.send(json.dumps({"type": "send", "sender": bob, "recipient": bob, "ciphertext": "forged"}))
    assert receive_json(ws)["type"] == "error"
    assert client.get("/messages/" + bob).json()["messages"] == []
    ws.send(json.dumps({"type": "send", "recipient": bob, "ciphertext": "authentic"}))
    assert receive_json(ws)["type"] == "sent"
    assert client.get("/messages/" + bob).json()["messages"][0]["from"] == alice


@pytest.mark.parametrize("token", ["", "made-up", "a" * 43, "x" * 10000])
def test_invalid_tokens(raw_client, token):
    assert raw_client.get("/messages/" + user_id("alice"), headers=headers(token)).status_code == 401


def test_expired_challenge(server_factory):
    client = HTTPClient(server_factory(AUTH_CHALLENGE_TTL=0.05).port)
    identity = user_id("device")
    nonce = challenge(client, identity)
    time.sleep(0.08)
    assert client.post("/auth/verify", json={"challenge": nonce, "signature": sign(identity, nonce)}).status_code == 401


def test_expired_http_and_websocket_sessions_require_new_proof(server_factory):
    server = server_factory(AUTH_SESSION_TTL=1)
    client = HTTPClient(server.port)
    identity = user_id("device")
    token = authenticate(client, identity)
    ws = websocket.create_connection(f"ws://127.0.0.1:{server.port}/ws/{identity}", header=headers(token), timeout=3)
    try:
        ws.send(json.dumps({"type": "health"}))
        assert json.loads(ws.recv())["status"] == "alive"
        assert ws.recv() == ""  # Server actively closes an idle, expired socket.
        assert client.get("/messages/" + identity, headers=headers(token)).status_code == 401
        fresh = authenticate(client, identity)
        assert client.get("/messages/" + identity, headers=headers(fresh)).status_code == 200
    finally:
        ws.close()


def test_restart_requires_reauthentication_but_preserves_key_derived_id(server_factory):
    server = server_factory()
    client = HTTPClient(server.port)
    identity = user_id("device")
    token = authenticate(client, identity)
    old_challenge = challenge(client, identity)
    server.stop()
    server.start()
    assert client.get("/messages/" + identity, headers=headers(token)).status_code == 401
    assert client.post("/auth/verify", json={
        "challenge": old_challenge, "signature": sign(identity, old_challenge),
    }).status_code == 401
    fresh = authenticate(client, identity)
    assert client.get("/messages/" + identity, headers=headers(fresh)).status_code == 200


def test_production_requires_tls_and_does_not_trust_forwarded_headers(server_factory):
    client = HTTPClient(server_factory(ALLOW_INSECURE_HTTP=False).port)
    response = client.post("/auth/challenge", json={"public_key": public_key(user_id("device"))},
                           headers={"X-Forwarded-Proto": "https"})
    assert response.status_code == 426
    assert client.get("/health").status_code == 200


def test_proof_cannot_be_relayed_from_another_server(raw_client):
    identity = user_id("device")
    nonce = challenge(raw_client, identity)
    assert raw_client.post("/auth/verify", json={
        "challenge": nonce,
        "signature": sign(identity, nonce, audience="https://attacker.example"),
    }).status_code == 401


def test_production_audience_ignores_attacker_host_header(server_factory):
    client = HTTPClient(server_factory(AUTH_ORIGIN="https://chat.example").port)
    response = client.post("/auth/challenge", json={"public_key": public_key(user_id("device"))},
                           headers={"Host": "attacker.example"})
    assert response.status_code == 200
    assert response.json()["audience"] == "https://chat.example"
