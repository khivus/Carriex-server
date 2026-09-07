import pytest

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
            "sender": "alice",
            "recipient": "bob",
            "ciphertext": "encrypted_data_abc123",
        })
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "ok"
        assert data["delivered"] is False
        assert data["message_count"] == 1

    def test_get_messages_empty(self, client):
        response = client.get("/messages/charlie")
        assert response.status_code == 200
        assert response.json()["messages"] == []

    def test_send_and_retrieve_message(self, client):
        response = client.post("/send", json={
            "sender": "alice",
            "recipient": "bob",
            "ciphertext": "encrypted_message_content",
        })
        assert response.status_code == 201
        response = client.get("/messages/bob")
        assert response.status_code == 200
        messages = response.json()["messages"]
        assert len(messages) == 1
        assert messages[0]["from"] == "alice"
        assert messages[0]["ciphertext"] == "encrypted_message_content"
        assert "timestamp" in messages[0]

    def test_get_messages_clears_after_fetch(self, client):
        client.post("/send", json={
            "sender": "alice",
            "recipient": "bob",
            "ciphertext": "msg1",
        })
        response = client.get("/messages/bob")
        assert len(response.json()["messages"]) == 1
        response = client.get("/messages/bob")
        assert response.json()["messages"] == []


class TestHTTPMessageRouting:
    def test_message_routes_to_correct_recipient(self, client):
        client.post("/send", json={
            "sender": "charlie",
            "recipient": "bob",
            "ciphertext": "msg_for_bob",
        })
        assert client.get("/messages/alice").json()["messages"] == []
        messages = client.get("/messages/bob").json()["messages"]
        assert len(messages) == 1
        assert messages[0]["from"] == "charlie"

    def test_multiple_messages_to_same_recipient(self, client):
        for i, sender in enumerate(["alice", "charlie", "diana"], start=1):
            client.post("/send", json={
                "sender": sender,
                "recipient": "bob",
                "ciphertext": f"message_{i}",
            })
        messages = client.get("/messages/bob").json()["messages"]
        assert len(messages) == 3
        assert messages[0]["from"] == "alice"
        assert messages[1]["from"] == "charlie"
        assert messages[2]["from"] == "diana"

    def test_multiple_recipients_are_isolated(self, client):
        client.post("/send", json={"sender": "charlie", "recipient": "alice", "ciphertext": "for_alice"})
        client.post("/send", json={"sender": "charlie", "recipient": "bob", "ciphertext": "for_bob"})
        alice = client.get("/messages/alice").json()["messages"]
        bob = client.get("/messages/bob").json()["messages"]
        assert len(alice) == 1
        assert alice[0]["ciphertext"] == "for_alice"
        assert len(bob) == 1
        assert bob[0]["ciphertext"] == "for_bob"
