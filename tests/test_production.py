"""Exercise the actual production TLS/WSS listener, including read deadlines."""
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest
import websocket

from auth_client import authenticate, user_id
from test_pairing import TLSClient


@pytest.fixture
def production(tmp_path):
    pytest.importorskip("gevent")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Carriex localhost test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    certificate, private = tmp_path / "test-cert.pem", tmp_path / "test-key.pem"
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    client = TLSClient(port, certificate)
    env = {**os.environ, "CARRIEX_DATA_DIR": str(tmp_path / "data"),
           "CARRIEX_AUTH_ORIGIN": f"https://127.0.0.1:{port}", "CARRIEX_REQUEST_TIMEOUT": "1"}
    log_path = tmp_path / "production.log"
    with log_path.open("w") as log:
        process = subprocess.Popen([sys.executable, "-m", "src.production", "--host", "127.0.0.1", "--port", str(port),
                                    "--certfile", str(certificate), "--keyfile", str(private)],
                                   cwd=Path(__file__).resolve().parents[1], env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            while process.poll() is None and time.monotonic() < deadline:
                try:
                    if client.get("/health").status_code == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.05)
            else:
                pytest.fail(log_path.read_text())
            yield client, port
        finally:
            process.terminate()
            process.wait(timeout=10)


def test_production_authenticates_tls_and_websocket_and_closes_revoked_session(production):
    client, port = production
    owner = user_id("production-owner")
    headers = {"Authorization": "Bearer " + authenticate(client, owner)}
    assert client.get(f"/messages/{owner}", headers=headers).status_code == 200
    ws = websocket.create_connection(f"wss://127.0.0.1:{port}/ws/{owner}", header=headers,
                                     sslopt={"context": client.context}, timeout=3)
    try:
        ws.send(json.dumps(dict(type="health")))
        assert json.loads(ws.recv())["status"] == "alive"
        assert client.request("DELETE", "/auth/sessions", headers=headers).status_code == 200
        assert ws.recv() == ""
    finally:
        ws.close()
    assert client.get("/health").status_code == 200


def test_production_closes_slow_headers_and_bounds_body_read(production):
    client, port = production
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        with client.context.wrap_socket(raw, server_hostname="127.0.0.1") as sock:
            sock.sendall(b"GET /hea")
            started = time.monotonic()
            try:
                response = sock.recv(4096)
                assert response == b"" or response.startswith(b"HTTP/1.1 4")
            except ssl.SSLError:
                pass
            assert time.monotonic() - started < 2.8
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        with client.context.wrap_socket(raw, server_hostname="127.0.0.1") as sock:
            sock.sendall(b"POST /auth/challenge HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
            response = sock.recv(4096)
            assert b"408" in response
    assert client.get("/health").status_code == 200
