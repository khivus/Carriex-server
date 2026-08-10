import json
import time
from .conftest import receive_json

class TestWebSocketConnection:
    def test_websocket_connection(self, websocket):
        ws = websocket("alice")
        assert ws.connected

    def test_websocket_health(self, websocket):
        ws = websocket("alice")
        ws.send(json.dumps({"type": "health"}))
        response = receive_json(ws)
        assert response == {"type": "health", "status": "alive"}

    def test_http_health_reports_websocket_connection(self, client, websocket):
        ws = websocket("alice")
        time.sleep(0.05)
        data = client.get("/health").get_json()
        assert data["status"] == "alive"
        assert data["websocket_users"] == 1
        assert data["websocket_clients"] == 1
        ws.close()


class TestWebSocketSend:
    def test_websocket_send_offline_recipient(self, websocket):
        ws = websocket("alice")
        ws.send(json.dumps({
            "type": "send",
            "recipient": "bob",
            "ciphertext": "encrypted_message",
        }))
        response = receive_json(ws)
        assert response["type"] == "sent"
        assert response["delivered"] is False
        assert response["message_count"] == 1

    def test_websocket_send_to_online_recipient(self, websocket):
        alice = websocket("alice")
        bob = websocket("bob")
        alice.send(json.dumps({
            "type": "send",
            "recipient": "bob",
            "ciphertext": "encrypted_message",
        }))
        sent = receive_json(alice)
        received = receive_json(bob)
        assert sent["type"] == "sent"
        assert sent["delivered"] is True
        assert received["type"] == "message"
        assert received["message"]["from"] == "alice"
        assert received["message"]["ciphertext"] == "encrypted_message"
        assert "timestamp" in received["message"]

    def test_http_send_to_online_websocket_client(self, client, websocket):
        bob = websocket("bob")
        response = client.post("/send", json={
            "sender": "alice",
            "recipient": "bob",
            "ciphertext": "encrypted_from_http",
        })
        assert response.status_code == 201
        data = response.get_json()
        assert data["delivered"] is True
        assert data["message_count"] == 0
        received = receive_json(bob)
        assert received["type"] == "message"
        assert received["message"]["from"] == "alice"
        assert received["message"]["ciphertext"] == "encrypted_from_http"

    def test_offline_message_is_delivered_when_user_connects(self, websocket):
        alice = websocket("alice")
        alice.send(json.dumps({
            "type": "send",
            "recipient": "bob",
            "ciphertext": "offline_message",
        }))
        sent = receive_json(alice)
        assert sent["delivered"] is False
        assert sent["message_count"] == 1
        bob = websocket("bob")
        received = receive_json(bob)
        assert received["type"] == "message"
        assert received["message"]["from"] == "alice"
        assert received["message"]["ciphertext"] == "offline_message"
