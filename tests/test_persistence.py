"""Black-box persistence and receipt behavior through live localhost servers."""
from auth_client import authenticate, user_id
from conftest import HTTPClient
import json


def authorized(client, identity):
    return {"Authorization": "Bearer " + authenticate(client, user_id(identity))}


def test_queue_survives_restart_and_ack_retires_ciphertext(server_factory, tmp_path):
    data_dir = str(tmp_path / "durable")
    alice, bob = user_id("alice"), user_id("bob")
    first = server_factory(MESSAGE_DATA_DIR=data_dir)
    client = HTTPClient(first.port)
    sent = client.post("/send", json={"id": "a" * 32, "sender": alice, "recipient": bob,
                                     "ciphertext": "opaque"}, headers=authorized(client, "alice"))
    assert sent.status_code == 201
    first.stop()

    second = server_factory(MESSAGE_DATA_DIR=data_dir)
    client = HTTPClient(second.port)
    alice_headers, bob_headers = authorized(client, "alice"), authorized(client, "bob")
    inbox = client.get("/messages/" + bob, headers=bob_headers).json()["messages"]
    assert len(inbox) == 1 and inbox[0]["id"] == "a" * 32
    assert client.get("/messages/" + bob, headers=bob_headers).json()["messages"] == inbox
    ack = client.post("/messages/" + bob + "/ack", json={"ids": ["a" * 32]}, headers=bob_headers)
    assert ack.json()["acknowledged"] == 1
    assert client.get("/messages/" + bob, headers=bob_headers).json()["messages"] == []
    assert client.get("/statuses/" + alice, headers=alice_headers).json()["statuses"] == [
        {"id": "a" * 32, "state": "received"}]


def test_retry_is_idempotent_and_conflicting_content_is_rejected(raw_client):
    alice, bob = user_id("alice"), user_id("bob")
    headers = authorized(raw_client, "alice")
    payload = {"id": "b" * 32, "sender": alice, "recipient": bob, "ciphertext": "same"}
    assert raw_client.post("/send", json=payload, headers=headers).status_code == 201
    assert raw_client.post("/send", json=payload, headers=headers).status_code == 201
    assert raw_client.post("/send", json={**payload, "ciphertext": "changed"}, headers=headers).status_code == 409
    inbox = raw_client.get("/messages/" + bob, headers=authorized(raw_client, "bob")).json()["messages"]
    assert len(inbox) == 1


def test_ack_requires_recipient_and_can_hide_receipt(raw_client):
    alice, bob = user_id("alice"), user_id("bob")
    alice_headers = authorized(raw_client, "alice")
    bob_headers = authorized(raw_client, "bob")
    payload = {"id": "c" * 32, "sender": alice, "recipient": bob, "ciphertext": "opaque"}
    assert raw_client.post("/send", json=payload, headers=alice_headers).status_code == 201
    assert raw_client.post("/messages/" + bob + "/ack", json={"ids": [payload["id"]]},
                           headers=alice_headers).status_code == 403
    assert raw_client.post("/messages/" + bob + "/ack",
                           json={"ids": [payload["id"]], "report_delivery": False},
                           headers=bob_headers).json()["acknowledged"] == 1
    assert raw_client.get("/messages/" + bob, headers=bob_headers).json()["messages"] == []
    assert raw_client.get("/statuses/" + alice, headers=alice_headers).json()["statuses"] == [
        {"id": payload["id"], "state": "sent"}]


def test_expired_message_is_not_delivered(server_factory):
    server = server_factory(MESSAGE_TTL_SECONDS=1)
    client = HTTPClient(server.port)
    alice, bob = user_id("alice"), user_id("bob")
    assert client.post("/send", json={"sender": alice, "recipient": bob, "ciphertext": "expired"},
                       headers=authorized(client, "alice")).status_code == 201
    import time
    time.sleep(1.1)
    assert client.get("/messages/" + bob,
                      headers=authorized(client, "bob")).json()["messages"] == []


def test_websocket_receipt_follows_recipient_ack(websocket, receive_json):
    alice = websocket(user_id("alice"))
    bob = websocket(user_id("bob"))
    message_id = "d" * 32
    alice.send(json.dumps({"type": "send", "id": message_id,
                           "recipient": user_id("bob"), "ciphertext": "opaque"}))
    assert receive_json(alice)["id"] == message_id
    assert receive_json(bob)["message"]["id"] == message_id
    bob.send(json.dumps({"type": "ack", "ids": [message_id]}))
    assert receive_json(bob) == {"type": "acknowledged", "count": 1}
    assert receive_json(alice) == {"type": "receipt", "id": message_id, "state": "received"}
