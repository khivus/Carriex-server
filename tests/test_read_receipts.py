"""Recipient viewing is optional, authenticated, durable and separate from delivery."""
import pytest
import json
from auth_client import user_id
from conftest import HTTPClient
from test_persistence import authorized


def send(client, message_id, sender="alice", recipient="bob"):
    assert client.post("/send", json={"id": message_id, "sender": user_id(sender),
                                     "recipient": user_id(recipient), "ciphertext": "opaque"},
                       headers=authorized(client, sender)).status_code == 201


def test_only_recipient_can_report_read_after_delivery_and_retry_is_idempotent(raw_client):
    client = raw_client
    message_id = "a" * 32
    send(client, message_id)
    path = f"/messages/{user_id('bob')}/read"
    payload = {"ids": [message_id]}
    bob = authorized(client, "bob")
    assert client.post(path, json=payload).status_code == 401
    assert client.post(path, json=payload, headers=authorized(client, "alice")).status_code == 403
    assert client.post(path, json=payload, headers=bob).json() == {"read": 0}
    assert client.post(f"/messages/{user_id('bob')}/ack", json=payload, headers=bob).json() == {"acknowledged": 1}
    statuses = f"/statuses/{user_id('alice')}"
    alice = authorized(client, "alice")
    assert client.get(statuses, headers=alice).json()["statuses"] == [{"id": message_id, "state": "received"}]
    assert client.post(path, json=payload, headers=bob).json() == {"read": 1}
    assert client.post(path, json=payload, headers=bob).json() == {"read": 0}
    assert client.get(statuses, headers=alice).json()["statuses"] == [{"id": message_id, "state": "read"}]


def test_quarantine_and_hidden_delivery_do_not_leak_read_status(raw_client):
    client = raw_client
    bob = authorized(client, "bob")
    for message_id, flags in [("b" * 32, {"quarantine": True}), ("c" * 32, {"report_delivery": False})]:
        send(client, message_id)
        client.post(f"/messages/{user_id('bob')}/ack", json={"ids": [message_id], **flags}, headers=bob)
        assert client.post(f"/messages/{user_id('bob')}/read", json={"ids": [message_id]}, headers=bob).json() == {"read": 0}
    send(client, "d" * 32, recipient="carol")
    assert client.post(f"/messages/{user_id('bob')}/read", json={"ids": ["d" * 32]}, headers=bob).json() == {"read": 0}


@pytest.mark.parametrize("payload", [None, {}, {"ids": "a" * 32}, {"ids": [1]}, {"ids": ["z" * 32]}, {"ids": ["a" * 32] * 501}])
def test_read_validation(raw_client, payload):
    response = raw_client.post(f"/messages/{user_id('bob')}/read", json=payload, headers=authorized(raw_client, "bob"))
    assert response.status_code == 400


def test_read_status_survives_restart(server_factory, tmp_path):
    first = server_factory(MESSAGE_DATA_DIR=str(tmp_path / "read-durable"))
    client = HTTPClient(first.port)
    send(client, "e" * 32)
    bob = authorized(client, "bob")
    payload = {"ids": ["e" * 32]}
    client.post(f"/messages/{user_id('bob')}/ack", json=payload, headers=bob)
    client.post(f"/messages/{user_id('bob')}/read", json=payload, headers=bob)
    first.stop()
    second = server_factory(MESSAGE_DATA_DIR=str(tmp_path / "read-durable"))
    client = HTTPClient(second.port)
    assert client.get(f"/statuses/{user_id('alice')}", headers=authorized(client, "alice")).json()["statuses"] == [
        {"id": "e" * 32, "state": "read"}]


def test_websocket_reports_delivery_then_read(raw_client, websocket, receive_json):
    alice, bob = user_id("alice"), user_id("bob")
    sender, recipient = websocket(alice), websocket(bob)
    message_id = "f" * 32
    send(raw_client, message_id)
    assert receive_json(recipient)["message"]["id"] == message_id
    recipient.send(json.dumps({"type": "ack", "ids": [message_id]}))
    assert receive_json(recipient) == {"type": "acknowledged", "count": 1}
    assert receive_json(sender) == {"type": "receipt", "id": message_id, "state": "received"}
    assert raw_client.post(f"/messages/{bob}/read", json={"ids": [message_id]}, headers=authorized(raw_client, "bob")).json() == {"read": 1}
    assert receive_json(sender) == {"type": "receipt", "id": message_id, "state": "read"}
