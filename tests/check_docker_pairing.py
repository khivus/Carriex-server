"""Optional real Docker check: python tests/check_docker_pairing.py.

Uses a uniquely named Compose project, temporary config and loopback ports only.
Its own test containers/volume are removed on exit; existing deployments are untouched.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request
import uuid

import websocket

ROOT = Path(__file__).resolve().parents[1]


def available_port(preferred=0):
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", preferred))
        except OSError:
            sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    project = "carriex-config-check-" + uuid.uuid4().hex[:10]
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CARRIEX_", "PAIRED_", "COMPOSE_"))}
    with tempfile.TemporaryDirectory(prefix="carriex-docker-config-") as temporary:
        config = Path(temporary) / ".env"
        command = ["docker", "compose", "--project-name", project, "--env-file", str(config),
                   "--file", str(ROOT / "compose.yaml")]

        def compose(*args, timeout=30):
            result = subprocess.run(command + list(args), cwd=ROOT, env=environment,
                                    capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", timeout=timeout)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            return result.stdout

        original_key = None
        try:
            for index, port in enumerate([available_port(443), available_port()]):
                config.write_text(f"CARRIEX_HOST=127.0.0.1\nCARRIEX_PORT={port}\n"
                                  f"CARRIEX_SERVER_NAME='Docker check {index}'\nPAIRED_BIND=127.0.0.1\n",
                                  encoding="utf-8")
                compose("up", "--build", "-d", timeout=180)
                if index == 0:
                    # Isolated writable bind mount: standard Compose does not mount host .env.
                    settings = Path(temporary) / "settings"
                    settings.mkdir(mode=0o777)
                    settings.chmod(0o777)
                    env_file = settings / ".env"
                    original = b"# Personal note\nCARRIEX_HOST=localhost\nCARRIEX_PORT=8443\n"
                    env_file.write_bytes(original)
                    env_file.chmod(0o666)
                    migrate = ("run", "--rm", "--no-deps", "--entrypoint", "python", "--volume",
                               f"{settings}:/settings", "server", "-m", "src.pairing", "--config",
                               "/settings/.env", "--migrate-config")
                    compose(*migrate)
                    migrated = env_file.read_bytes()
                    backups = list(settings.glob(".env.backup-*"))
                    assert len(backups) == 1
                    # Backups are 0600 and owned by the container user. A Linux host
                    # runner may have a different UID; verify as the writer instead
                    # of relaxing the backup's permissions for the test.
                    backup_digest = compose(
                        "run", "--rm", "--no-deps", "--entrypoint", "python", "--volume",
                        f"{settings}:/settings", "server", "-c",
                        "import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())",
                        f"/settings/{backups[0].name}").strip()
                    assert backup_digest == hashlib.sha256(original).hexdigest()
                    if os.name != "nt":
                        assert backups[0].stat().st_mode & 0o777 == 0o600
                    assert b"# 08 | INTERNET EXPOSURE" in migrated
                    assert b"\nCARRIEX_HOST=localhost\n" in migrated
                    compose(*migrate)
                    assert env_file.read_bytes() == migrated
                    assert len(list(settings.glob(".env.backup-*"))) == 1
                    assert sorted(item.name for item in settings.iterdir()) == sorted([".env", backups[0].name])
                    print("PASS: Docker host-config migration, exact backup, repeat run, no identity files", flush=True)
                deadline = time.monotonic() + 30
                while True:
                    try:
                        data = json.loads(compose("exec", "-T", "server", "cat", "/var/lib/carriex/pairing.json"))
                        context = ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(base64.b64decode(data["certificate"])))
                        expected = f"https://127.0.0.1" + ("" if port == 443 else f":{port}")
                        assert data["url"] == expected and data["name"] == f"Docker check {index}"
                        with urllib.request.urlopen(expected + "/health", context=context, timeout=3) as response:
                            assert json.load(response)["status"] == "alive"
                        break
                    except (OSError, RuntimeError, ValueError, AssertionError):
                        if time.monotonic() >= deadline:
                            raise RuntimeError(compose("logs", "server")) from None
                        time.sleep(0.2)
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                key = x509.load_der_x509_certificate(base64.b64decode(data["certificate"])).public_key()
                encoded = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                if original_key is not None:
                    assert encoded == original_key, "Config edits replaced the server identity"
                original_key = encoded
                from auth_client import authenticate, user_id
                from test_pairing import TLSClient
                cert_file = Path(temporary) / "public.pem"
                cert_file.write_text(ssl.DER_cert_to_PEM_cert(base64.b64decode(data["certificate"])), encoding="utf-8")
                client = TLSClient(port, cert_file)
                identity = user_id("docker-config-check")
                token = authenticate(client, identity)
                ws = websocket.create_connection(f"wss://127.0.0.1:{port}/ws/{identity}",
                                                 header={"Authorization": "Bearer " + token},
                                                 sslopt={"context": context}, timeout=3)
                try:
                    ws.send(json.dumps({"type": "health"}))
                    assert json.loads(ws.recv())["status"] == "alive"
                finally:
                    ws.close()
                print(f"PASS: .env port {port}, pinned HTTPS, authenticated WSS, stable identity", flush=True)
        finally:
            # Only the uniquely named test project and its new test volume are removed.
            if config.exists():
                compose("down", "--volumes", "--remove-orphans")


if __name__ == "__main__":
    main()
