import json
from datetime import datetime, timezone
from threading import Lock


message_store = {}
websocket_connections = {}
store_lock = Lock()


def create_message(sender, recipient, ciphertext):
    """Create the opaque message object routed by the server."""
    return {
        "from": sender,
        "ciphertext": ciphertext,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def store_message(recipient, message):
    """Store a message for a recipient."""
    with store_lock:
        if recipient not in message_store:
            message_store[recipient] = []

        message_store[recipient].append(message)


def add_websocket(user_id, ws):
    """Register an active WebSocket connection."""
    with store_lock:
        if user_id not in websocket_connections:
            websocket_connections[user_id] = []

        websocket_connections[user_id].append(ws)


def remove_websocket(user_id, ws):
    """Remove a WebSocket connection."""
    with store_lock:
        connections = websocket_connections.get(user_id)

        if not connections:
            return

        if ws in connections:
            connections.remove(ws)

        if not connections:
            del websocket_connections[user_id]


def send_to_connected_user(recipient, message):
    """Send a message to all active WebSocket connections of a user."""
    with store_lock:
        connections = list(websocket_connections.get(recipient, []))

    delivered = False
    dead_connections = []

    for ws in connections:
        try:
            ws.send(json.dumps({"type": "message", "message": message}))
            delivered = True
        except Exception:
            dead_connections.append(ws)

    for ws in dead_connections:
        remove_websocket(recipient, ws)

    return delivered


def route_message(sender, recipient, ciphertext):
    """Route an encrypted message to the recipient or offline queue."""
    message = create_message(sender, recipient, ciphertext)

    delivered = send_to_connected_user(recipient, message)

    if not delivered:
        store_message(recipient, message)

    with store_lock:
        queued_count = len(message_store.get(recipient, []))

    return message, delivered, queued_count
