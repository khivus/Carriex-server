from auth_client import user_id
"""
Pytest test suite for the Carriex Flask/WebSocket message server.

Tests:
- HTTP message sending
- HTTP message retrieval
- HTTP health check
- HTTP validation and method handling
- Message routing and data integrity
- WebSocket connection
- WebSocket health
- WebSocket sending and receiving
- Online delivery
- Offline queue delivery
- Multiple WebSocket clients
- WebSocket validation
"""

import json
from datetime import datetime

import pytest
from websocket import WebSocketTimeoutException

# ============================================================================
# HTTP: BASIC FUNCTIONALITY
# ============================================================================

class TestHTTPBasicFunctionality:

    def test_health_check(self, client):
        response = client.get("/health")

        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "alive"
        assert data["websocket_users"] == 0
        assert data["websocket_clients"] == 0

    def test_send_message_success(self, client):
        response = client.post("/send", json={
            "sender": user_id("alice"),
            "recipient": user_id("bob"),
            "ciphertext": "encrypted_data_abc123",
        })

        assert response.status_code == 201

        data = response.json()
        assert data["status"] == "ok"
        assert data["delivered"] is False
        assert data["message_count"] == 1

    def test_get_messages_empty(self, client):
        response = client.get("/messages/" + user_id("charlie"))

        assert response.status_code == 200
        assert response.json()["messages"] == []

    def test_send_and_retrieve_message(self, client):
        response = client.post("/send", json={
            "sender": user_id("alice"),
            "recipient": user_id("bob"),
            "ciphertext": "encrypted_message_content",
        })

        assert response.status_code == 201

        response = client.get("/messages/" + user_id("bob"))

        assert response.status_code == 200

        messages = response.json()["messages"]

        assert len(messages) == 1
        assert messages[0]["from"] == user_id("alice")
        assert messages[0]["ciphertext"] == "encrypted_message_content"
        assert "timestamp" in messages[0]

    def test_get_messages_waits_for_acknowledgement(self, client):
        client.post("/send", json={
            "sender": user_id("alice"),
            "recipient": user_id("bob"),
            "ciphertext": "msg1",
        })

        response = client.get("/messages/" + user_id("bob"))
        assert len(response.json()["messages"]) == 1

        response = client.get("/messages/" + user_id("bob"))
        message_id = response.json()["messages"][0]["id"]
        assert client.post("/messages/" + user_id("bob") + "/ack", json={"ids": [message_id]}).status_code == 200
        assert client.get("/messages/" + user_id("bob")).json()["messages"] == []


# ============================================================================
# HTTP: ERROR HANDLING
# ============================================================================

class TestHTTPErrorHandling:

    @pytest.mark.parametrize(
        "payload",
        [
            {
                "recipient": user_id("bob"),
                "ciphertext": "encrypted_data",
            },
            {
                "sender": user_id("alice"),
                "ciphertext": "encrypted_data",
            },
            {
                "sender": user_id("alice"),
                "recipient": user_id("bob"),
            },
            {
                "sender": "",
                "recipient": user_id("bob"),
                "ciphertext": "encrypted_data",
            },
            {
                "sender": user_id("alice"),
                "recipient": "",
                "ciphertext": "encrypted_data",
            },
            {
                "sender": user_id("alice"),
                "recipient": user_id("bob"),
                "ciphertext": "",
            },
        ],
    )
    def test_send_invalid_payload(self, client, payload):
        response = client.post("/send", json=payload)

        assert response.status_code == 400

        data = response.json()
        assert "error" in data
        assert "missing fields" in data["error"]

    def test_send_invalid_json(self, client):
        response = client.post(
            "/send",
            data="not json",
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 400

        data = response.json()
        assert data["error"] == "invalid JSON"

    def test_send_empty_body(self, client):
        response = client.post("/send")

        assert response.status_code == 400

        data = response.json()
        assert data["error"] == "invalid JSON"


# ============================================================================
# HTTP: ROUTING
# ============================================================================

class TestHTTPMessageRouting:

    def test_message_routes_to_correct_recipient(self, client):
        client.post("/send", json={
            "sender": user_id("charlie"),
            "recipient": user_id("bob"),
            "ciphertext": "msg_for_bob",
        })

        assert client.get("/messages/" + user_id("alice")).json()["messages"] == []

        messages = client.get("/messages/" + user_id("bob")).json()["messages"]

        assert len(messages) == 1
        assert messages[0]["from"] == user_id("charlie")

    def test_multiple_messages_to_same_recipient(self, client):
        for i, sender in enumerate(
            [user_id("alice"), user_id("charlie"), user_id("diana")],
            start=1,
        ):
            client.post("/send", json={
                "sender": sender,
                "recipient": user_id("bob"),
                "ciphertext": f"message_{i}",
            })

        messages = client.get("/messages/" + user_id("bob")).json()["messages"]

        assert len(messages) == 3
        assert messages[0]["from"] == user_id("alice")
        assert messages[1]["from"] == user_id("charlie")
        assert messages[2]["from"] == user_id("diana")

    def test_multiple_recipients_are_isolated(self, client):
        client.post("/send", json={
            "sender": user_id("charlie"),
            "recipient": user_id("alice"),
            "ciphertext": "for_alice",
        })

        client.post("/send", json={
            "sender": user_id("charlie"),
            "recipient": user_id("bob"),
            "ciphertext": "for_bob",
        })

        alice = client.get("/messages/" + user_id("alice")).json()["messages"]
        bob = client.get("/messages/" + user_id("bob")).json()["messages"]

        assert len(alice) == 1
        assert alice[0]["ciphertext"] == "for_alice"

        assert len(bob) == 1
        assert bob[0]["ciphertext"] == "for_bob"


# ============================================================================
# HTTP: EDGE CASES AND DATA INTEGRITY
# ============================================================================

class TestHTTPEdgeCases:

    def test_distinct_device_ids(self, client):
        response = client.post("/send", json={
            "sender": user_id("user_alice-123"),
            "recipient": user_id("user_bob.456"),
            "ciphertext": "msg",
        })

        assert response.status_code == 201

        messages = client.get(
            "/messages/" + user_id("user_bob.456")
        ).json()["messages"]

        assert len(messages) == 1
        assert messages[0]["from"] == user_id("user_alice-123")

    def test_very_long_ciphertext(self, client):
        ciphertext = "x" * 10000

        response = client.post("/send", json={
            "sender": user_id("alice"),
            "recipient": user_id("bob"),
            "ciphertext": ciphertext,
        })

        assert response.status_code == 201

        messages = client.get("/messages/" + user_id("bob")).json()["messages"]

        assert len(messages) == 1
        assert messages[0]["ciphertext"] == ciphertext

    def test_duplicate_messages_are_stored(self, client):
        payload = {
            "sender": user_id("alice"),
            "recipient": user_id("bob"),
            "ciphertext": "duplicate_content",
        }

        client.post("/send", json=payload)
        client.post("/send", json=payload)

        messages = client.get("/messages/" + user_id("bob")).json()["messages"]

        assert len(messages) == 2
        assert messages[0]["ciphertext"] == messages[1]["ciphertext"]

    def test_sender_and_recipient_same(self, client):
        response = client.post("/send", json={
            "sender": user_id("alice"),
            "recipient": user_id("alice"),
            "ciphertext": "note_to_self",
        })

        assert response.status_code == 201

        messages = client.get("/messages/" + user_id("alice")).json()["messages"]

        assert len(messages) == 1

    def test_ids_for_independently_generated_keys(self, client):
        response = client.post("/send", json={
            "sender": user_id("alice_🚀"),
            "recipient": user_id("bob_中文"),
            "ciphertext": "msg",
        })

        assert response.status_code == 201

        messages = client.get("/messages/" + user_id("bob_中文")).json()["messages"]

        assert len(messages) == 1
        assert messages[0]["from"] == user_id("alice_🚀")

    def test_ciphertext_not_modified(self, client):
        ciphertext = 'abc123!@#$%^&*()_+-=[]{}|;:,.<>?/~`'

        client.post("/send", json={
            "sender": user_id("alice"),
            "recipient": user_id("bob"),
            "ciphertext": ciphertext,
        })

        messages = client.get("/messages/" + user_id("bob")).json()["messages"]

        assert messages[0]["ciphertext"] == ciphertext

    def test_timestamp_is_valid_iso_format(self, client):
        client.post("/send", json={
            "sender": user_id("alice"),
            "recipient": user_id("bob"),
            "ciphertext": "msg",
        })

        timestamp = client.get(
            "/messages/" + user_id("bob")
        ).json()["messages"][0]["timestamp"]

        parsed = datetime.fromisoformat(timestamp)

        assert parsed is not None


# ============================================================================
# HTTP: RESPONSE FORMAT
# ============================================================================

class TestHTTPResponseFormat:

    def test_send_response_structure(self, client):
        response = client.post("/send", json={
            "sender": user_id("alice"),
            "recipient": user_id("bob"),
            "ciphertext": "msg",
        })

        data = response.json()

        assert set(data) == {
            "status",
            "delivered",
            "message_count",
            "id",
        }

        assert data["status"] == "ok"
        assert isinstance(data["delivered"], bool)
        assert isinstance(data["message_count"], int)

    def test_get_messages_response_structure(self, client):
        client.post("/send", json={
            "sender": user_id("alice"),
            "recipient": user_id("bob"),
            "ciphertext": "msg",
        })

        data = client.get("/messages/" + user_id("bob")).json()

        assert "messages" in data
        assert isinstance(data["messages"], list)

        message = data["messages"][0]

        assert set(message) == {
            "from",
            "ciphertext",
            "timestamp",
            "id",
        }


# ============================================================================
# HTTP: METHOD VALIDATION
# ============================================================================

class TestHTTPMethods:

    def test_get_send_not_allowed(self, client):
        assert client.get("/send").status_code == 405

    def test_post_messages_not_allowed(self, client):
        assert client.post("/messages/" + user_id("bob")).status_code == 405


# ============================================================================
# WEBSOCKET: CONNECTION AND HEALTH
# ============================================================================

class TestWebSocketConnection:

    def test_websocket_connection(self, websocket, receive_json):
        ws = websocket(user_id("alice"))

        assert ws.connected

    def test_websocket_health(self, websocket, receive_json):
        ws = websocket(user_id("alice"))

        ws.send(json.dumps({
            "type": "health",
        }))

        response = receive_json(ws)

        assert response == {
            "type": "health",
            "status": "alive",
        }

    def test_http_health_reports_websocket_connection(
        self,
        client,
        websocket,
        receive_json,
    ):
        ws = websocket(user_id("alice"))

        data = client.get("/health").json()

        assert data["status"] == "alive"
        assert data["websocket_users"] == 1
        assert data["websocket_clients"] == 1

        ws.close()


# ============================================================================
# WEBSOCKET: SEND
# ============================================================================

class TestWebSocketSend:

    def test_websocket_send_offline_recipient(
        self,
        websocket,
        receive_json,
    ):
        ws = websocket(user_id("alice"))

        ws.send(json.dumps({
            "type": "send",
            "recipient": user_id("bob"),
            "ciphertext": "encrypted_message",
        }))

        response = receive_json(ws)

        assert response["type"] == "sent"
        assert response["delivered"] is False
        assert response["message_count"] == 1

    def test_websocket_send_to_online_recipient(
        self,
        websocket,
        receive_json,
    ):
        alice = websocket(user_id("alice"))
        bob = websocket(user_id("bob"))

        alice.send(json.dumps({
            "type": "send",
            "recipient": user_id("bob"),
            "ciphertext": "encrypted_message",
        }))

        sent = receive_json(alice)
        received = receive_json(bob)

        assert sent["type"] == "sent"
        assert sent["delivered"] is True

        assert received["type"] == "message"
        assert received["message"]["from"] == user_id("alice")
        assert received["message"]["ciphertext"] == "encrypted_message"
        assert "timestamp" in received["message"]

    def test_http_send_to_online_websocket_client(
        self,
        client,
        websocket,
        receive_json,
    ):
        bob = websocket(user_id("bob"))

        response = client.post("/send", json={
            "sender": user_id("alice"),
            "recipient": user_id("bob"),
            "ciphertext": "encrypted_from_http",
        })

        assert response.status_code == 201

        data = response.json()
        assert data["delivered"] is True
        assert data["message_count"] == 1

        received = receive_json(bob)

        assert received["type"] == "message"
        assert received["message"]["from"] == user_id("alice")
        assert received["message"]["ciphertext"] == "encrypted_from_http"

    def test_offline_message_is_delivered_when_user_connects(
        self,
        websocket,
        receive_json,
    ):
        alice = websocket(user_id("alice"))

        alice.send(json.dumps({
            "type": "send",
            "recipient": user_id("bob"),
            "ciphertext": "offline_message",
        }))

        sent = receive_json(alice)

        assert sent["delivered"] is False
        assert sent["message_count"] == 1

        bob = websocket(user_id("bob"))

        received = receive_json(bob)

        assert received["type"] == "message"
        assert received["message"]["from"] == user_id("alice")
        assert received["message"]["ciphertext"] == "offline_message"


# ============================================================================
# WEBSOCKET: MULTIPLE CLIENTS
# ============================================================================

class TestWebSocketRouting:

    def test_messages_are_routed_to_correct_user(
        self,
        websocket,
        receive_json,
    ):
        alice = websocket(user_id("alice"))
        bob = websocket(user_id("bob"))
        charlie = websocket(user_id("charlie"))

        alice.send(json.dumps({
            "type": "send",
            "recipient": user_id("bob"),
            "ciphertext": "for_bob",
        }))

        sent = receive_json(alice)
        received = receive_json(bob)

        assert sent["delivered"] is True
        assert received["message"]["ciphertext"] == "for_bob"

        # Charlie must not receive Alice's message.
        charlie.settimeout(0.1)

        with pytest.raises(WebSocketTimeoutException):
            charlie.recv()

    def test_multiple_messages_preserve_order(
        self,
        websocket,
        receive_json,
    ):
        alice = websocket(user_id("alice"))
        bob = websocket(user_id("bob"))

        for i in range(3):
            alice.send(json.dumps({
                "type": "send",
                "recipient": user_id("bob"),
                "ciphertext": f"message_{i}",
            }))

            sent = receive_json(alice)
            assert sent["delivered"] is True

        messages = [
            receive_json(bob),
            receive_json(bob),
            receive_json(bob),
        ]

        assert [
            message["message"]["ciphertext"]
            for message in messages
        ] == [
            "message_0",
            "message_1",
            "message_2",
        ]

    def test_multiple_connections_for_same_user(
        self,
        websocket,
        receive_json,
    ):
        bob1 = websocket(user_id("bob"))
        bob2 = websocket(user_id("bob"))
        alice = websocket(user_id("alice"))

        alice.send(json.dumps({
            "type": "send",
            "recipient": user_id("bob"),
            "ciphertext": "message",
        }))

        assert receive_json(alice)["delivered"] is True

        message1 = receive_json(bob1)
        message2 = receive_json(bob2)

        assert message1["message"]["ciphertext"] == "message"
        assert message2["message"]["ciphertext"] == "message"


# ============================================================================
# WEBSOCKET: VALIDATION
# ============================================================================

class TestWebSocketValidation:

    def test_invalid_json(self, websocket, receive_json):
        ws = websocket(user_id("alice"))

        ws.send("not json")

        response = receive_json(ws)

        assert response["type"] == "error"
        assert response["error"] == "invalid JSON"

    def test_unknown_message_type(self, websocket, receive_json):
        ws = websocket(user_id("alice"))

        ws.send(json.dumps({
            "type": "unknown",
        }))

        response = receive_json(ws)

        assert response["type"] == "error"
        assert response["error"] == "unknown message type"

    def test_send_missing_recipient(self, websocket, receive_json):
        ws = websocket(user_id("alice"))

        ws.send(json.dumps({
            "type": "send",
            "ciphertext": "encrypted",
        }))

        response = receive_json(ws)

        assert response["type"] == "error"
        assert response["error"] == "missing fields (recipient, ciphertext)"

    def test_send_missing_ciphertext(self, websocket, receive_json):
        ws = websocket(user_id("alice"))

        ws.send(json.dumps({
            "type": "send",
            "recipient": user_id("bob"),
        }))

        response = receive_json(ws)

        assert response["type"] == "error"
        assert response["error"] == "missing fields (recipient, ciphertext)"

    def test_empty_recipient(self, websocket, receive_json):
        ws = websocket(user_id("alice"))

        ws.send(json.dumps({
            "type": "send",
            "recipient": "",
            "ciphertext": "encrypted",
        }))

        response = receive_json(ws)

        assert response["type"] == "error"
        assert response["error"] == "missing fields (recipient, ciphertext)"

    def test_empty_ciphertext(self, websocket, receive_json):
        ws = websocket(user_id("alice"))

        ws.send(json.dumps({
            "type": "send",
            "recipient": user_id("bob"),
            "ciphertext": "",
        }))

        response = receive_json(ws)

        assert response["type"] == "error"
        assert response["error"] == "missing fields (recipient, ciphertext)"


# ============================================================================
# NOT FOUND / METHOD HANDLERS
# ============================================================================

class TestErrorHandlers:

    def test_not_found(self, client):
        response = client.get("/does-not-exist")

        assert response.status_code == 404
        assert response.json()["error"] == "endpoint not found"

    def test_wrong_method(self, client):
        response = client.put("/health")

        assert response.status_code == 405
        assert response.json()["error"] == "method not allowed"


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
