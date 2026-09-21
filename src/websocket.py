import json
import time

from flask import g

from src.auth import valid_user_id

from src.store import (
    add_websocket,
    message_store,
    remove_websocket,
    route_message,
    store_lock,
)


def register_websocket(sock):
    """Register WebSocket routes on the Flask-Sock instance."""

    @sock.route("/ws/<user_id>")
    def websocket(ws, user_id):
        # Authentication and path ownership were checked before the upgrade.
        user_id = g.user_id
        ws.auth_expires_at = g.auth_expires_at
        add_websocket(user_id, ws)

        try:
            with store_lock:
                queued_messages = message_store.pop(user_id, [])

            for index, message in enumerate(queued_messages):
                try:
                    if time.monotonic() >= ws.auth_expires_at:
                        raise TimeoutError("Session expired")
                    ws.send(json.dumps({
                        "type": "message",
                        "message": message,
                    }))
                except Exception:
                    # Restore the failed message and every remaining unsent item.
                    with store_lock:
                        message_store[user_id] = queued_messages[index:] + message_store.get(user_id, [])
                    return

            while True:
                remaining = ws.auth_expires_at - time.monotonic()
                if remaining <= 0:
                    ws.close(reason=1008, message="Authentication expired")
                    break
                data = ws.receive(timeout=remaining)

                if data is None:
                    continue

                if time.monotonic() >= ws.auth_expires_at:
                    ws.close(reason=1008, message="Authentication expired")
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

                    if "sender" in data and data["sender"] != user_id:
                        ws.send(json.dumps({"type": "error", "error": "Sender does not match authenticated device"}))
                        continue
                    if not valid_user_id(recipient) or not isinstance(ciphertext, str):
                        ws.send(json.dumps({"type": "error", "error": "Invalid recipient or ciphertext"}))
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
