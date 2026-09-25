from auth_client import user_id
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
        response = client.post("/messages/" + user_id("bob") + "/ack", json={"ids": [message_id]})
        assert response.status_code == 200
        assert client.get("/messages/" + user_id("bob")).json()["messages"] == []


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
        for i, sender in enumerate([user_id("alice"), user_id("charlie"), user_id("diana")], start=1):
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
        client.post("/send", json={"sender": user_id("charlie"), "recipient": user_id("alice"), "ciphertext": "for_alice"})
        client.post("/send", json={"sender": user_id("charlie"), "recipient": user_id("bob"), "ciphertext": "for_bob"})
        alice = client.get("/messages/" + user_id("alice")).json()["messages"]
        bob = client.get("/messages/" + user_id("bob")).json()["messages"]
        assert len(alice) == 1
        assert alice[0]["ciphertext"] == "for_alice"
        assert len(bob) == 1
        assert bob[0]["ciphertext"] == "for_bob"
