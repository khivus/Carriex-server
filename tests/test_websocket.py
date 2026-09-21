from auth_client import user_id
import json

class TestWebSocketConnection:
    def test_websocket_connection(self, websocket, receive_json):
        ws = websocket(user_id("alice"))
        assert ws.connected

    def test_websocket_health(self, websocket, receive_json):
        ws = websocket(user_id("alice"))
        ws.send(json.dumps({"type": "health"}))
        response = receive_json(ws)
        assert response == {"type": "health", "status": "alive"}

    def test_http_health_reports_websocket_connection(self, client, websocket, receive_json):
        ws = websocket(user_id("alice"))
        data = client.get("/health").json()
        assert data["status"] == "alive"
        assert data["websocket_users"] == 1
        assert data["websocket_clients"] == 1
        ws.close()


class TestWebSocketSend:
    def test_websocket_send_offline_recipient(self, websocket, receive_json):
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

    def test_websocket_send_to_online_recipient(self, websocket, receive_json):
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

    def test_http_send_to_online_websocket_client(self, client, websocket, receive_json):
        bob = websocket(user_id("bob"))
        response = client.post("/send", json={
            "sender": user_id("alice"),
            "recipient": user_id("bob"),
            "ciphertext": "encrypted_from_http",
        })
        assert response.status_code == 201
        data = response.json()
        assert data["delivered"] is True
        assert data["message_count"] == 0
        received = receive_json(bob)
        assert received["type"] == "message"
        assert received["message"]["from"] == user_id("alice")
        assert received["message"]["ciphertext"] == "encrypted_from_http"

    def test_offline_message_is_delivered_when_user_connects(self, websocket, receive_json):
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

class TestWebSocketReconnect:
    def test_reconnect_delivers_offline_backlog_once(self, client, websocket, receive_json):
        import time
        bob = websocket(user_id("bob"))
        bob.close()
        deadline = time.monotonic() + 2
        while client.get("/health").json()["websocket_clients"]:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        for number in range(10):
            response = client.post("/send", json={
                "sender": user_id("alice"), "recipient": user_id("bob"), "ciphertext": str(number),
            })
            assert response.status_code == 201
            assert response.json()["delivered"] is False
        bob = websocket(user_id("bob"))
        assert [receive_json(bob)["message"]["ciphertext"] for _ in range(10)] == [str(n) for n in range(10)]
        bob.send(json.dumps({"type": "health"}))
        assert receive_json(bob) == {"type": "health", "status": "alive"}
        assert client.get("/messages/" + user_id("bob")).json()["messages"] == []

    def test_closing_old_socket_keeps_new_connection(self, client, websocket, receive_json):
        old = websocket(user_id("bob"))
        current = websocket(user_id("bob"))
        old.close()
        response = client.post("/send", json={
            "sender": user_id("alice"), "recipient": user_id("bob"), "ciphertext": "after-reconnect",
        })
        assert response.json()["delivered"] is True
        assert receive_json(current)["message"]["ciphertext"] == "after-reconnect"
