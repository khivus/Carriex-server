import json

from src.store import (
    add_websocket,
    message_store,
    remove_websocket,
    route_message,
    store_lock,
    store_message,
)


def register_websocket(sock):
    """Register WebSocket routes on the Flask-Sock instance."""

    @sock.route("/ws/<user_id>")
    def websocket(user_id, ws):
        add_websocket(user_id, ws)

        try:
            with store_lock:
                queued_messages = message_store.pop(user_id, [])

            for message in queued_messages:
                try:
                    ws.send(json.dumps({
                        "type": "message",
                        "message": message,
                    }))
                except Exception:
                    store_message(user_id, message)
                    return

            while True:
                data = ws.receive()

                if data is None:
                    break

                if not isinstance(data, str):
                    ws.send(json.dumps({
                        "type": "error",
                        "error": "message must be JSON text",
                    }))
                    continue

                try:
                    data = json.loads(data)
                except (TypeError, ValueError):
                    ws.send(json.dumps({
                        "type": "error",
                        "error": "invalid JSON",
                    }))
                    continue

                if not isinstance(data, dict):
                    ws.send(json.dumps({
                        "type": "error",
                        "error": "JSON message must be an object",
                    }))
                    continue

                message_type = data.get("type")

                if message_type == "health":
                    ws.send(json.dumps({
                        "type": "health",
                        "status": "alive",
                    }))
                    continue

                if message_type == "send":
                    recipient = data.get("recipient")
                    ciphertext = data.get("ciphertext")

                    if not recipient or not ciphertext:
                        ws.send(json.dumps({
                            "type": "error",
                            "error": "missing fields (recipient, ciphertext)",
                        }))
                        continue

                    _, delivered, queued_count = route_message(
                        user_id,
                        recipient,
                        ciphertext,
                    )

                    ws.send(json.dumps({
                        "type": "sent",
                        "delivered": delivered,
                        "message_count": queued_count,
                    }))
                    continue

                ws.send(json.dumps({
                    "type": "error",
                    "error": "unknown message type",
                }))

        except Exception:
            pass

        finally:
            remove_websocket(user_id, ws)
