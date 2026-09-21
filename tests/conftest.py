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
from auth_client import authenticate, user_id


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
def server_factory(tmp_path):
    """Start Flask in a subprocess; never import application state into pytest."""
    servers = []

    class RunningServer:
        def __init__(self, config):
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                self.port = sock.getsockname()[1]
            self.config = {"ALLOW_INSECURE_HTTP": True, **config}
            self.process = None
            self.log_path = tmp_path / f"server-{self.port}.log"
            self.log = self.log_path.open("w", encoding="utf-8")

        def start(self):
            self.process = subprocess.Popen(
                [sys.executable, "-c",
                 "import json,sys; from src.app import create_app; "
                 "create_app(json.loads(sys.argv[1])).run(host='127.0.0.1', "
                 "port=int(sys.argv[2]), threaded=True, use_reloader=False)",
                 json_module.dumps(self.config), str(self.port)],
                cwd=Path(__file__).resolve().parents[1], stdout=self.log, stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and self.process.poll() is None:
                try:
                    response = HTTPClient(self.port).get("/health")
                    if response.status_code == 200 and response.json()["status"] == "alive":
                        break
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.05)
            else:
                pytest.fail("Local server failed to start:\n" + self.log_path.read_text(encoding="utf-8"))

        def stop(self):
            if self.process is None:
                return
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def launch(**config):
        server = RunningServer(config)
        servers.append(server)
        server.start()
        return server

    yield launch
    for server in servers:
        server.stop()
        server.log.close()


@pytest.fixture
def server_port(server_factory):
    return server_factory().port


@pytest.fixture
def raw_client(server_port):
    return HTTPClient(server_port)


@pytest.fixture
def sessions(raw_client):
    tokens = {}

    def token(identity):
        if identity not in tokens:
            tokens[identity] = authenticate(raw_client, identity)
        return tokens[identity]

    return token


@pytest.fixture
def client(server_port, sessions):
    class AuthenticatedClient(HTTPClient):
        def request(self, method, path, *, json=None, data=None, headers=None):
            headers = dict(headers or {})
            if path == "/send" or path.startswith("/messages/"):
                identity = user_id("alice")
                if path.startswith("/messages/"):
                    identity = path.removeprefix("/messages/")
                elif isinstance(json, dict) and json.get("sender"):
                    identity = json["sender"]
                headers.setdefault("Authorization", "Bearer " + sessions(identity))
            return super().request(method, path, json=json, data=data, headers=headers)

    return AuthenticatedClient(server_port)


@pytest.fixture
def websocket(server_port, sessions):
    connections = []

    def connect(user_id):
        ws = websocket_client.create_connection(
            f"ws://127.0.0.1:{server_port}/ws/{quote(user_id, safe='')}",
            timeout=2, http_no_proxy=["127.0.0.1"],
            header={"Authorization": "Bearer " + sessions(user_id)},
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
