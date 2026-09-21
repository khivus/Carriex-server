from auth_client import user_id
import pytest
import json

class TestHTTPErrorHandling:
    @pytest.mark.parametrize("payload", [
        {"recipient": user_id("bob"), "ciphertext": "encrypted_data"},
        {"sender": user_id("alice"), "ciphertext": "encrypted_data"},
        {"sender": user_id("alice"), "recipient": user_id("bob")},
        {"sender": "", "recipient": user_id("bob"), "ciphertext": "encrypted_data"},
        {"sender": user_id("alice"), "recipient": "", "ciphertext": "encrypted_data"},
        {"sender": user_id("alice"), "recipient": user_id("bob"), "ciphertext": ""},
    ])
    def test_send_invalid_payload(self, client, payload):
        response = client.post("/send", json=payload)
        assert response.status_code == 400
        assert "error" in response.json()

    def test_send_invalid_json(self, client):
        response = client.post("/send", data="not json", headers={"Content-Type": "application/json"})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid JSON"

    def test_send_empty_body(self, client):
        response = client.post("/send")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid JSON"


class TestHTTPMethods:
    def test_get_send_not_allowed(self, client):
        assert client.get("/send").status_code == 405

    def test_post_messages_not_allowed(self, client):
        assert client.post("/messages/" + user_id("bob")).status_code == 405


class TestErrorHandlers:
    def test_not_found(self, client):
        response = client.get("/does-not-exist")
        assert response.status_code == 404
        assert response.json()["error"] == "endpoint not found"

    def test_wrong_method(self, client):
        response = client.put("/health")
        assert response.status_code == 405
        assert response.json()["error"] == "method not allowed"


class TestWebSocketValidation:
    def test_invalid_json(self, websocket, receive_json):
        ws = websocket(user_id("alice"))
        ws.send("not json")
        response = receive_json(ws)
        assert response["type"] == "error"
        assert response["error"] == "invalid JSON"

    def test_unknown_message_type(self, websocket, receive_json):
        ws = websocket(user_id("alice"))
        ws.send(json.dumps({"type": "unknown"}))
        response = receive_json(ws)
        assert response["type"] == "error"
        assert response["error"] == "unknown message type"

    def test_send_missing_recipient(self, websocket, receive_json):
        ws = websocket(user_id("alice"))
        ws.send(json.dumps({"type": "send", "ciphertext": "encrypted"}))
        response = receive_json(ws)
        assert response["type"] == "error"

    def test_send_missing_ciphertext(self, websocket, receive_json):
        ws = websocket(user_id("alice"))
        ws.send(json.dumps({"type": "send", "recipient": user_id("bob")}))
        response = receive_json(ws)
        assert response["type"] == "error"
