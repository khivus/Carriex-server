"""Exercise the pairing CLI and TLS listener as external processes."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from PIL import Image
import websocket

from auth_client import authenticate, user_id
from conftest import HTTPResponse


ROOT = Path(__file__).resolve().parents[1]


def generate(directory, address="https://127.0.0.1:8443", name="Home server", success=True):
    result = subprocess.run(
        [sys.executable, "-m", "src.pairing", "--config", str(directory.parent / "unused.env"), "--data-dir", str(directory),
         "--address", address, "--name", name, "--pair-only"],
        cwd=ROOT, capture_output=True, text=True, timeout=20,
    )
    assert (result.returncode == 0) == success, result.stdout + result.stderr
    return result


def bundle(directory):
    return json.loads((directory / "pairing.json").read_text("utf-8"))


def fingerprint(data):
    cert = x509.load_der_x509_certificate(base64.b64decode(data["certificate"]))
    key = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(key).hexdigest()


def test_pairing_contains_only_public_data_and_reuses_identity(tmp_path):
    directory = tmp_path / "identity"
    generate(directory)
    first = bundle(directory)
    key_digest = hashlib.sha256((directory / "server-key.pem").read_bytes()).digest()
    assert set(first) == {"type", "version", "name", "url", "certificate"}
    assert first["type"] == "carriex-server" and first["version"] == 1
    assert "PRIVATE KEY" not in (directory / "pairing.json").read_text()
    cert = x509.load_der_x509_certificate(base64.b64decode(first["certificate"]))
    cert.verify_directly_issued_by(cert)
    with Image.open(directory / "pairing.png") as image:
        assert image.width == image.height and image.width >= 300
    assert "pairing.png" in (directory / "pairing.html").read_text()
    generate(directory, name="Renamed server")
    assert fingerprint(bundle(directory)) == fingerprint(first)
    assert hashlib.sha256((directory / "server-key.pem").read_bytes()).digest() == key_digest
    assert bundle(directory)["name"] == "Renamed server"
    if os.name != "nt":
        assert (directory / "server-key.pem").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("address", ["http://127.0.0.1:8443", "https://0.0.0.0", "https://[::]",
                                     "https://224.0.0.1", "https://user:pass@example.com",
                                     "https://example.com/path", "https://example.com?x=1",
                                     "https://example.com#fragment", "https://example.com:0",
                                     "https://example.com:65536", "https://bad host", ""])
def test_invalid_pairing_addresses_rejected(tmp_path, address):
    directory = tmp_path / "identity"
    generate(directory, address=address, success=False)
    assert not (directory / "server-key.pem").exists()


def test_does_not_change_permissions_on_unrelated_directory(tmp_path):
    (tmp_path / "unrelated.txt").write_text("keep")
    generate(tmp_path, success=False)
    assert (tmp_path / "unrelated.txt").read_text() == "keep"
    assert not (tmp_path / "server-key.pem").exists()


def test_missing_identity_key_is_not_silently_replaced(tmp_path):
    directory = tmp_path / "identity"
    generate(directory)
    (directory / "server-key.pem").unlink()  # Deliberately damage only this test's temporary identity.
    result = generate(directory, success=False)
    assert "key is missing" in result.stderr
    assert not (directory / "server-key.pem").exists()


def test_certificate_renews_with_same_key_and_updated_address(tmp_path):
    directory = tmp_path / "identity"
    generate(directory)
    original = fingerprint(bundle(directory))
    generate(directory, address="https://localhost:8443")
    assert fingerprint(bundle(directory)) == original
    cert = x509.load_pem_x509_certificate((directory / "server-cert.pem").read_bytes())
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == ["localhost"]
    key = serialization.load_pem_private_key((directory / "server-key.pem").read_bytes(), password=None)
    now = datetime.now(timezone.utc)
    expired = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=2)).not_valid_after(now - timedelta(days=1))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
               .sign(key, hashes.SHA256()))
    (directory / "server-cert.pem").write_bytes(expired.public_bytes(serialization.Encoding.PEM))
    generate(directory, address="https://localhost:8443")
    assert fingerprint(bundle(directory)) == original
    renewed = x509.load_pem_x509_certificate((directory / "server-cert.pem").read_bytes())
    assert renewed.not_valid_after_utc > now + timedelta(days=300)


def test_html_escapes_operator_supplied_name(tmp_path):
    directory = tmp_path / "identity"
    generate(directory, name="<script>alert('name')</script>")
    page = (directory / "pairing.html").read_text("utf-8")
    assert "<script>" not in page
    assert "&lt;script&gt;" in page


class TLSClient:
    def __init__(self, port, certificate):
        self.port = port
        self.context = ssl.create_default_context(cafile=str(certificate))

    def request(self, method, path, *, json=None, headers=None):
        headers = dict(headers or {})
        data = None
        if json is not None:
            data = __import__("json").dumps(json)
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=3, context=self.context)
        try:
            connection.request(method, path, data, headers)
            return HTTPResponse(connection.getresponse())
        finally:
            connection.close()

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)


def test_actual_paired_tls_launcher_authenticates_http_and_websocket(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    directory = tmp_path / "identity"
    generate(directory, address=f"https://127.0.0.1:{port}")
    client = TLSClient(port, directory / "server-cert.pem")
    log_path = tmp_path / "server.log"
    with log_path.open("w") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "src.pairing", "--config", str(tmp_path / "unused.env"), "--data-dir", str(directory), "--bind", "127.0.0.1"],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    if client.get("/health").status_code == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.05)
            else:
                pytest.fail(log_path.read_text())
            identity = user_id("paired-device")
            token = authenticate(client, identity)
            headers = {"Authorization": "Bearer " + token}
            assert client.get("/messages/" + identity, headers=headers).status_code == 200
            ws = websocket.create_connection(f"wss://127.0.0.1:{port}/ws/{identity}",
                                             header=headers, sslopt={"context": client.context}, timeout=3)
            try:
                ws.send(json.dumps({"type": "health"}))
                assert json.loads(ws.recv())["status"] == "alive"
            finally:
                ws.close()
            wrong_trust = ssl.create_default_context()
            connection = http.client.HTTPSConnection("127.0.0.1", port, context=wrong_trust, timeout=3)
            try:
                with pytest.raises(ssl.SSLCertVerificationError):
                    connection.request("GET", "/health")
            finally:
                connection.close()
        finally:
            process.terminate()
            process.wait(timeout=10)
