import json
import pytest
from src.app import app
from src.store import message_store, websocket_connections


@pytest.fixture
def client():
    """Return a Flask test client with clean server state."""
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client

    # Make every test independent.
    message_store.clear()
    websocket_connections.clear()


@pytest.fixture
def websocket():
    """
    Return a helper for opening a real WebSocket connection.
    """
    pytest.importorskip("websocket")

    import websocket as websocket_client

    connections = []

    def connect(user_id):
        ws = websocket_client.create_connection(
            f"ws://127.0.0.1:5000/ws/{user_id}",
            timeout=2,
        )
        connections.append(ws)
        return ws

    yield connect

    for ws in connections:
        try:
            ws.close()
        except Exception:
            pass


@pytest.fixture
def receive_json():
    """Return a helper to receive one JSON WebSocket message."""
    def _receive(ws, timeout=2):
        ws.settimeout(timeout)
        return json.loads(ws.recv())
    return _receive
