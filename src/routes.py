from flask import Blueprint, g, jsonify, request

from src.auth import valid_user_id

from src._version import __version__

from src.store import message_store, route_message, store_lock, websocket_connections


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

    _, delivered, queued_count = route_message(g.user_id, recipient, ciphertext)

    return jsonify({
        "status": "ok",
        "delivered": delivered,
        "message_count": queued_count,
    }), 201


@api.route("/messages/<user_id>", methods=["GET"])
def get_messages(user_id):
    """GET /messages/<user_id>"""
    with store_lock:
        messages = message_store.pop(user_id, [])

    return jsonify({"messages": messages}), 200


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
