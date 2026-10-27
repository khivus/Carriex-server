from flask import Blueprint, g, jsonify, request

from src.auth import valid_user_id

from src._version import __version__
from src.compatibility import COMPATIBILITY

import re

from src.store import MessageTooLargeError, acknowledge_messages, route_message, send_event, store, store_lock, websocket_connections


api = Blueprint("api", __name__)


@api.route("/send", methods=["POST"])
def send_message():
    """POST /send"""
    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not data:
        return jsonify({"error": "invalid JSON"}), 400

    sender = data.get("sender")
    recipient = data.get("recipient")
    ciphertext = data.get("ciphertext")

    if not sender or not recipient or not ciphertext:
        return jsonify({
            "error": "missing fields (sender, recipient, ciphertext)"
        }), 400

    if sender != g.user_id:
        return jsonify(error="Sender does not match authenticated device"), 403
    if not valid_user_id(recipient) or not isinstance(ciphertext, str):
        return jsonify(error="Invalid recipient or ciphertext"), 400

    message_id = data.get("id")
    if message_id is not None and (not isinstance(message_id, str) or re.fullmatch(r"[0-9a-f]{32}", message_id) is None):
        return jsonify(error="Invalid message ID"), 400
    try:
        message, delivered, queued_count = route_message(g.user_id, recipient, ciphertext, message_id)
    except MessageTooLargeError as exc:
        return jsonify(error=str(exc)), 413
    except OverflowError as exc:
        return jsonify(error=str(exc)), 429
    except ValueError as exc:
        return jsonify(error=str(exc)), 409

    return jsonify({
        "status": "ok",
        "delivered": delivered,
        "message_count": queued_count,
        "id": message["id"],
    }), 201


@api.route("/messages/<user_id>", methods=["GET"])
def get_messages(user_id):
    """GET /messages/<user_id>"""
    after = request.args.get("after", "0")
    if not after.isascii() or not after.isdigit() or len(after) > 18:
        return jsonify(error="Invalid inbox cursor"), 400
    messages = store().inbox(user_id, int(after))

    return jsonify({"messages": messages}), 200


@api.post("/messages/<user_id>/policy")
def inbox_policy(user_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Invalid inbox policy"), 400
    contacts, blocked = data.get("contacts"), data.get("blocked")
    if any(not isinstance(values, list) or len(values) > 128 or any(not valid_user_id(value) for value in values)
           for values in (contacts, blocked)):
        return jsonify(error="At most 128 contacts and 128 blocked IDs are supported"), 400
    try:
        store().policy(user_id, contacts, blocked)
    except OverflowError as exc:
        return jsonify(error=str(exc)), 429
    return jsonify(status="ok"), 200


@api.route("/messages/<user_id>/ack", methods=["POST"])
def ack_messages(user_id):
    data = request.get_json(silent=True)
    ids = data.get("ids") if isinstance(data, dict) else None
    if not isinstance(ids, list) or len(ids) > 500 or any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None for value in ids
    ):
        return jsonify(error="Invalid message IDs"), 400
    report_delivery = data.get("report_delivery", True)
    if not isinstance(report_delivery, bool):
        return jsonify(error="Invalid report_delivery"), 400
    quarantine = data.get("quarantine", False)
    if not isinstance(quarantine, bool):
        return jsonify(error="Invalid quarantine flag"), 400
    if quarantine:
        return jsonify(acknowledged=store().quarantine(user_id, ids)), 200
    return jsonify(acknowledged=acknowledge_messages(user_id, ids, report_delivery)), 200


@api.route("/statuses/<user_id>", methods=["GET"])
def get_statuses(user_id):
    return jsonify(statuses=store().statuses(user_id)), 200


@api.post("/messages/<user_id>/read")
def read_messages(user_id):
    """Optional recipient-reported viewing, separate from durable delivery."""
    data = request.get_json(silent=True)
    ids = data.get("ids") if isinstance(data, dict) else None
    if not isinstance(ids, list) or len(ids) > 500 or any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None for value in ids
    ):
        return jsonify(error="Invalid message IDs"), 400
    receipts = store().mark_read(user_id, ids)
    for sender, message_id in receipts:
        send_event(sender, {"type": "receipt", "id": message_id, "state": "read"})
    return jsonify(read=len(receipts)), 200


@api.route("/health", methods=["GET"])
def health():
    """GET /health"""
    with store_lock:
        connected_users = len(websocket_connections)
        connected_clients = sum(
            len(connections) for connections in websocket_connections.values()
        )

    return jsonify({
        "status": "alive",
        "compatibility": COMPATIBILITY,
        "version": __version__,
        "websocket_users": connected_users,
        "websocket_clients": connected_clients,
    }), 200


def register_routes(app):
    app.register_blueprint(api)

    @app.errorhandler(404)
    def handle_not_found(_error):
        return jsonify({"error": "endpoint not found"}), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(_error):
        return jsonify({"error": "method not allowed"}), 405
