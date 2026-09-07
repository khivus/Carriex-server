"""Integration fixtures using a real, isolated localhost server per test."""
import http.client
import json as json_module
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.parse import quote

import pytest
import websocket as websocket_client


class HTTPResponse:
    def __init__(self, response):
        self.status_code = response.status
        self.headers = dict(response.getheaders())
        self.content = response.read()

    def json(self):
        return json_module.loads(self.content)


class HTTPClient:
    def __init__(self, port):
        self.port = port

    def request(self, method, path, *, json=None, data=None, headers=None):
        headers = dict(headers or {})
        if json is not None:
            data = json_module.dumps(json).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            data = data.encode("utf-8")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        try:
            connection.request(method, quote(path, safe="/%?=&"), body=data, headers=headers)
            return HTTPResponse(connection.getresponse())
        finally:
            connection.close()

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)

    def put(self, path, **kwargs):
        return self.request("PUT", path, **kwargs)


@pytest.fixture
def server_port(tmp_path):
    """Start Flask in a subprocess; never import application state into pytest."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    log_path = tmp_path / "server.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "flask", "--app", "src.app:app",
             "run", "--host", "127.0.0.1", "--port", str(port),
             "--no-debugger", "--no-reload", "--with-threads"],
            cwd=Path(__file__).resolve().parents[1],
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    response = HTTPClient(port).get("/health")
                    if response.status_code == 200 and response.json()["status"] == "alive":
                        break
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.05)
            else:
                pytest.fail("Local server failed to start:\n" + log_path.read_text(encoding="utf-8"))
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@pytest.fixture
def client(server_port):
    return HTTPClient(server_port)


@pytest.fixture
def websocket(server_port):
    connections = []

    def connect(user_id):
        ws = websocket_client.create_connection(
            f"ws://127.0.0.1:{server_port}/ws/{quote(user_id, safe='')}",
            timeout=2, http_no_proxy=["127.0.0.1"],
        )
        connections.append(ws)
        # Wait for registration without consuming queued messages from the socket.
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            count = HTTPClient(server_port).get("/health").json()["websocket_clients"]
            if count == sum(connection.connected for connection in connections):
                return ws
            time.sleep(0.01)
        pytest.fail("WebSocket client was not registered by the server")

    yield connect
    for ws in connections:
        ws.close()


@pytest.fixture
def receive_json():
    def receive(ws, timeout=2):
        ws.settimeout(timeout)
        return json_module.loads(ws.recv())
    return receive
