import json
import re
import time

from flask import g

from src.auth import valid_user_id

from src.store import (
    acknowledge_messages,
    add_websocket,
    remove_websocket,
    route_message,
    store,
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
            queued_messages = store().inbox(user_id)

            for message in queued_messages:
                try:
                    if time.monotonic() >= ws.auth_expires_at:
                        raise TimeoutError("Session expired")
                    ws.send(json.dumps({
                        "type": "message",
                        "message": message,
                    }))
                except Exception:
                    # Messages remain queued until the recipient acknowledges them.
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

                if message_type == "ack":
                    ids = data.get("ids")
                    if not isinstance(ids, list) or len(ids) > 500 or any(
                        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None for value in ids
                    ):
                        ws.send(json.dumps({"type": "error", "error": "Invalid message IDs"}))
                        continue
                    report_delivery = data.get("report_delivery", True)
                    if not isinstance(report_delivery, bool):
                        ws.send(json.dumps({"type": "error", "error": "Invalid report_delivery"}))
                        continue
                    ws.send(json.dumps({"type": "acknowledged", "count": acknowledge_messages(user_id, ids, report_delivery)}))
                    continue

                if message_type == "send":
                    recipient = data.get("recipient")
                    ciphertext = data.get("ciphertext")
                    message_id = data.get("id")

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

                    if message_id is not None and (not isinstance(message_id, str) or re.fullmatch(r"[0-9a-f]{32}", message_id) is None):
                        ws.send(json.dumps({"type": "error", "error": "Invalid message ID"}))
                        continue

                    try:
                        message, delivered, queued_count = route_message(user_id, recipient, ciphertext, message_id)
                    except (ValueError, OverflowError) as exc:
                        ws.send(json.dumps({"type": "error", "error": str(exc)}))
                        continue

                    ws.send(json.dumps({
                        "type": "sent",
                        "delivered": delivered,
                        "message_count": queued_count,
                        "id": message["id"],
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
