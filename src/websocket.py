import json
import re
import time
from threading import Lock
import secrets

from flask import Response, current_app, g, request

from src.auth import valid_user_id
from src.auth import store as auth_store
from src.security import checked_json, throttled
from src.socket_limits import BoundedServer

from src.store import (
    acknowledge_messages,
    add_websocket,
    remove_websocket,
    route_message,
    store,
)


def register_websocket(app):
    """Reserve admission atomically before accepting the WebSocket upgrade."""
    slots, lock = {}, Lock()

    @app.before_request
    def admit_socket():
        if request.endpoint != "websocket" or not hasattr(g, "user_id"):
            return None
        source = request.remote_addr or "unknown"
        with lock:
            if (len(slots) >= app.config["WS_GLOBAL_LIMIT"] or
                sum(owner == g.user_id for owner, _ in slots.values()) >= app.config["WS_DEVICE_LIMIT"] or
                sum(address == source for _, address in slots.values()) >= app.config["WS_IP_LIMIT"]):
                return throttled(5, "WebSocket connection capacity reached; retry later")
            g.socket_slot = secrets.token_hex(16)
            slots[g.socket_slot] = (g.user_id, source)

    @app.teardown_request
    def release_socket(_error):
        slot = getattr(g, "socket_slot", None)
        if slot:
            with lock:
                slots.pop(slot, None)

    class SocketResponse(Response):
        def __init__(self, mode):
            super().__init__()
            self.mode = mode

        def __call__(self, *args, **kwargs):
            if self.mode == "gunicorn":
                raise StopIteration()
            if self.mode == "werkzeug":
                return super().__call__(*args, **kwargs)
            return []

    @app.route("/ws/<user_id>", websocket=True)
    def websocket(user_id):
        # Authentication and path ownership were checked before the upgrade.
        ws = BoundedServer(request.environ, app.config, **app.config["SOCK_SERVER_OPTIONS"])
        user_id = g.user_id
        ws.auth_expires_at = g.auth_expires_at
        ws.auth_header = request.headers.get("Authorization", "")
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
                    return SocketResponse(ws.mode)

            while True:
                remaining = ws.auth_expires_at - time.monotonic()
                if remaining <= 0:
                    ws.close(reason=1008, message="Authentication expired")
                    break
                if auth_store().session(ws.auth_header) is None:
                    ws.close(reason=1008, message="Authentication revoked")
                    break
                data = ws.receive(timeout=min(remaining, 1))

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
                    data = checked_json(data)
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
            try:
                ws.close()
            except Exception:
                pass
        return SocketResponse(ws.mode)
