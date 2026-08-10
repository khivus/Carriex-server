import pytest
import json
from .conftest import receive_json

class TestHTTPErrorHandling:
    @pytest.mark.parametrize("payload", [
        {"recipient": "bob", "ciphertext": "encrypted_data"},
        {"sender": "alice", "ciphertext": "encrypted_data"},
        {"sender": "alice", "recipient": "bob"},
        {"sender": "", "recipient": "bob", "ciphertext": "encrypted_data"},
        {"sender": "alice", "recipient": "", "ciphertext": "encrypted_data"},
        {"sender": "alice", "recipient": "bob", "ciphertext": ""},
    ])
    def test_send_invalid_payload(self, client, payload):
        response = client.post("/send", json=payload)
        assert response.status_code == 400
        assert "error" in response.get_json()

    def test_send_invalid_json(self, client):
        response = client.post("/send", data="not json", content_type="application/json")
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid JSON"

    def test_send_empty_body(self, client):
        response = client.post("/send")
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid JSON"


class TestHTTPMethods:
    def test_get_send_not_allowed(self, client):
        assert client.get("/send").status_code == 405

    def test_post_messages_not_allowed(self, client):
        assert client.post("/messages/bob").status_code == 405


class TestErrorHandlers:
    def test_not_found(self, client):
        response = client.get("/does-not-exist")
        assert response.status_code == 404
        assert response.get_json()["error"] == "endpoint not found"

    def test_wrong_method(self, client):
        response = client.put("/health")
        assert response.status_code == 405
        assert response.get_json()["error"] == "method not allowed"


class TestWebSocketValidation:
    def test_invalid_json(self, websocket):
        ws = websocket("alice")
        ws.send("not json")
        response = receive_json(ws)
        assert response["type"] == "error"
        assert response["error"] == "invalid JSON"

    def test_unknown_message_type(self, websocket):
        ws = websocket("alice")
        ws.send(json.dumps({"type": "unknown"}))
        response = receive_json(ws)
        assert response["type"] == "error"
        assert response["error"] == "unknown message type"

    def test_send_missing_recipient(self, websocket):
        ws = websocket("alice")
        ws.send(json.dumps({"type": "send", "ciphertext": "encrypted"}))
        response = receive_json(ws)
        assert response["type"] == "error"

    def test_send_missing_ciphertext(self, websocket):
        ws = websocket("alice")
        ws.send(json.dumps({"type": "send", "recipient": "bob"}))
        response = receive_json(ws)
        assert response["type"] == "error"
