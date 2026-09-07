import pytest
from datetime import datetime

class TestHTTPEdgeCases:
    def test_special_characters_in_username(self, client):
        response = client.post("/send", json={"sender": "user_alice-123", "recipient": "user_bob.456", "ciphertext": "msg"})
        assert response.status_code == 201
        messages = client.get("/messages/user_bob.456").json()["messages"]
        assert len(messages) == 1
        assert messages[0]["from"] == "user_alice-123"

    def test_very_long_ciphertext(self, client):
        ciphertext = "x" * 10000
        response = client.post("/send", json={"sender": "alice", "recipient": "bob", "ciphertext": ciphertext})
        assert response.status_code == 201
        messages = client.get("/messages/bob").json()["messages"]
        assert len(messages) == 1
        assert messages[0]["ciphertext"] == ciphertext

    def test_duplicate_messages_are_stored(self, client):
        payload = {"sender": "alice", "recipient": "bob", "ciphertext": "duplicate_content"}
        client.post("/send", json=payload)
        client.post("/send", json=payload)
        messages = client.get("/messages/bob").json()["messages"]
        assert len(messages) == 2

    def test_sender_and_recipient_same(self, client):
        response = client.post("/send", json={"sender": "alice", "recipient": "alice", "ciphertext": "note_to_self"})
        assert response.status_code == 201
        messages = client.get("/messages/alice").json()["messages"]
        assert len(messages) == 1

    def test_unicode_usernames(self, client):
        response = client.post("/send", json={"sender": "alice_🚀", "recipient": "bob_中文", "ciphertext": "msg"})
        assert response.status_code == 201
        messages = client.get("/messages/bob_中文").json()["messages"]
        assert len(messages) == 1
        assert messages[0]["from"] == "alice_🚀"

    def test_ciphertext_not_modified(self, client):
        ciphertext = 'abc123!@#$%^&*()_+-=[]{}|;:,.<>?/~`'
        client.post("/send", json={"sender": "alice", "recipient": "bob", "ciphertext": ciphertext})
        messages = client.get("/messages/bob").json()["messages"]
        assert messages[0]["ciphertext"] == ciphertext

    def test_timestamp_is_valid_iso_format(self, client):
        client.post("/send", json={"sender": "alice", "recipient": "bob", "ciphertext": "msg"})
        timestamp = client.get("/messages/bob").json()["messages"][0]["timestamp"]
        parsed = datetime.fromisoformat(timestamp)
        assert parsed is not None


class TestHTTPResponseFormat:
    def test_send_response_structure(self, client):
        response = client.post("/send", json={"sender": "alice", "recipient": "bob", "ciphertext": "msg"})
        data = response.json()
        assert set(data) == {"status", "delivered", "message_count"}
        assert data["status"] == "ok"

    def test_get_messages_response_structure(self, client):
        client.post("/send", json={"sender": "alice", "recipient": "bob", "ciphertext": "msg"})
        data = client.get("/messages/bob").json()
        assert "messages" in data
        message = data["messages"][0]
        assert set(message) == {"from", "ciphertext", "timestamp"}
