"""CLI/config regression checks; never import the running application."""
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest

from test_pairing import TLSClient, bundle, fingerprint

ROOT = Path(__file__).resolve().parents[1]


def run(tmp_path, text, *args, success=True, environment=None):
    config = tmp_path / "server.env"
    config.write_text(text, encoding="utf-8")
    env = {key: value for key, value in os.environ.items() if not key.startswith("CARRIEX_")}
    env.update(environment or {})
    result = subprocess.run([sys.executable, "-m", "src.pairing", "--config", str(config),
                             "--data-dir", str(tmp_path / "identity"), *args], cwd=ROOT,
                            env=env, capture_output=True, text=True, timeout=20)
    assert (result.returncode == 0) == success, result.stdout + result.stderr
    return result


@pytest.mark.parametrize("port", [443, 8443, 18443])
def test_one_config_port_controls_url_and_listener(tmp_path, port):
    result = run(tmp_path, f"CARRIEX_HOST=192.168.0.34\nCARRIEX_PORT={port}\n", "--check-config")
    suffix = "" if port == 443 else f":{port}"
    assert f"Server: https://192.168.0.34{suffix}\n" in result.stdout
    assert f"Listening: 0.0.0.0:{port}\n" in result.stdout
    assert not (tmp_path / "identity").exists()


def test_cli_https_default_port_is_443_and_explicit_mapping_is_reported(tmp_path):
    text = "CARRIEX_HOST=192.168.0.34\nCARRIEX_PORT=8443\n"
    result = run(tmp_path, text, "--address", "https://127.0.0.1", "--check-config")
    assert "Listening: 0.0.0.0:443" in result.stdout
    result = run(tmp_path, text, "--address", "https://127.0.0.1", "--port", "8443", "--check-config")
    assert "Port mapping required: phones reach 443; this process listens on 8443" in result.stdout


def test_config_changes_update_pairing_without_replacing_private_key(tmp_path):
    run(tmp_path, "CARRIEX_HOST=127.0.0.1\nCARRIEX_PORT=8443\nCARRIEX_SERVER_NAME='First server'\n", "--pair-only")
    directory = tmp_path / "identity"
    original = bundle(directory)
    private = hashlib.sha256((directory / "server-key.pem").read_bytes()).digest()
    qr = (directory / "pairing.png").read_bytes()
    run(tmp_path, "CARRIEX_HOST=localhost\nCARRIEX_PORT=443\nCARRIEX_SERVER_NAME='Renamed server'\n", "--pair-only")
    updated = bundle(directory)
    assert updated["url"] == "https://localhost" and updated["name"] == "Renamed server"
    assert updated["certificate"] != original["certificate"]
    assert (directory / "pairing.png").read_bytes() != qr
    assert fingerprint(updated) == fingerprint(original)
    assert hashlib.sha256((directory / "server-key.pem").read_bytes()).digest() == private


def test_public_pairing_files_are_copied_to_configured_existing_directory(tmp_path):
    destination = tmp_path / "phone-pairing"
    destination.mkdir()
    config = f"CARRIEX_HOST=localhost\nCARRIEX_PAIRING_EXPORT_DIR={destination}\n"
    run(tmp_path, config, "--pair-only")
    identity = tmp_path / "identity"
    for filename in ("pairing.html", "pairing.png", "pairing.json"):
        assert (destination / filename).read_bytes() == (identity / filename).read_bytes()
    assert not (destination / "server-key.pem").exists()
    first = (destination / "pairing.json").read_bytes()
    run(tmp_path, config.replace("localhost", "127.0.0.1"), "--pair-only")
    assert (destination / "pairing.json").read_bytes() != first
    assert (destination / "pairing.json").read_bytes() == (identity / "pairing.json").read_bytes()


def test_missing_pairing_export_directory_is_created_on_startup_only(tmp_path):
    destination = tmp_path / "new" / "pairing"
    config = f"CARRIEX_HOST=localhost\nCARRIEX_PAIRING_EXPORT_DIR={destination}\n"
    result = run(tmp_path, config, "--check-config")
    assert "will be created on startup" in result.stdout
    assert not destination.exists()
    assert not (tmp_path / "identity").exists()
    run(tmp_path, config, "--pair-only")
    assert (destination / "pairing.html").is_file()
    assert (destination / "pairing.png").is_file()
    assert (destination / "pairing.json").is_file()


def test_pairing_export_path_must_be_a_directory(tmp_path):
    destination = tmp_path / "pairing.txt"
    destination.write_text("keep")
    result = run(tmp_path, f"CARRIEX_HOST=localhost\nCARRIEX_PAIRING_EXPORT_DIR={destination}\n",
                 "--pair-only", success=False)
    assert "is not a directory" in result.stderr
    assert destination.read_text() == "keep"
    assert not (tmp_path / "identity").exists()


def test_pairing_export_cannot_be_inside_private_identity_directory(tmp_path):
    destination = tmp_path / "identity" / "public"
    result = run(tmp_path, f"CARRIEX_HOST=localhost\nCARRIEX_PAIRING_EXPORT_DIR={destination}\n",
                 "--check-config", success=False)
    assert "outside the private identity directory" in result.stderr
    assert not (tmp_path / "identity" / "server-key.pem").exists()


@pytest.mark.parametrize("text", [
    "CARRIEX_HOST=localhost\nCARRIEX_PORT=nope", "CARRIEX_HOST=localhost\nCARRIEX_PORT=0",
    "CARRIEX_HOST=localhost\nCARRIEX_PORT=65536", "CARRIEX_HOST=https://localhost",
    "CARRIEX_HOST=0.0.0.0", "CARRIEX_PORT=443", "CARRIEX_HOST='unterminated",
    "CARRIEX_HOST=localhost\nCARRIEX_HOST=other", "CARRIEX_HOTS=localhost",
    "CARRIEX_HOST=localhost\nCARRIEX_PUBLIC_URL=https://localhost",
    "CARRIEX_HOST=localhost\nCARRIEX_SERVER_NAME=", "CARRIEX_HOST=localhost\nCARRIEX_LISTEN_PORT=nope",
])
def test_bad_config_fails_before_touching_identity(tmp_path, text):
    run(tmp_path, text, "--pair-only", success=False)
    assert not (tmp_path / "identity").exists()


def test_statistics_mode_and_retention_are_explicit_and_validated(tmp_path):
    text = "CARRIEX_HOST=localhost\nCARRIEX_STATISTICS=1\nCARRIEX_STATISTICS_RETENTION_DAYS=7\n"
    result = run(tmp_path, text, "--check-config")
    assert "Statistics: enabled (retention 7 days)" in result.stdout
    assert "Statistics: disabled" in run(tmp_path, text, "--no-statistics", "--check-config").stdout
    run(tmp_path, text.replace("=7", "=0"), "--check-config", success=False)
    run(tmp_path, text.replace("STATISTICS=1", "STATISTICS=invalid"), "--check-config", success=False)


def test_environment_overrides_file_and_cli_overrides_environment(tmp_path):
    text = "CARRIEX_HOST=localhost\nCARRIEX_PORT=8443"
    result = run(tmp_path, text, "--check-config", environment={"CARRIEX_PORT": "443"})
    assert "Listening: 0.0.0.0:443" in result.stdout
    result = run(tmp_path, text, "--address", "https://127.0.0.1:19443", "--check-config", environment={"CARRIEX_PORT": "443"})
    assert "Listening: 0.0.0.0:19443" in result.stdout


def test_init_config_preserves_legacy_values_and_does_not_create_keys(tmp_path):
    run(tmp_path, "HOST=127.0.0.1\nPORT=5000\n", "--address", "https://192.168.0.34:443", "--name", "Home", "--init-config")
    text = (tmp_path / "server.env").read_text()
    assert "HOST=127.0.0.1\nPORT=5000\n" in text
    assert "CARRIEX_HOST='192.168.0.34'" in text and "CARRIEX_PORT='443'" in text
    assert not (tmp_path / "identity").exists()


@pytest.mark.parametrize("requested_port", [0, 443])
def test_real_tls_listener_uses_config_port_without_cli_port(tmp_path, requested_port):
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", requested_port))
        except OSError:
            if requested_port == 443:
                pytest.skip("Port 443 is already occupied or requires OS privileges")
            raise
        port = sock.getsockname()[1]
    run(tmp_path, f"CARRIEX_HOST=127.0.0.1\nCARRIEX_PORT={port}\nCARRIEX_BIND=127.0.0.1\n", "--pair-only")
    client = TLSClient(port, tmp_path / "identity" / "server-cert.pem")
    with (tmp_path / "server.log").open("w") as log:
        process = subprocess.Popen([sys.executable, "-m", "src.pairing", "--config", str(tmp_path / "server.env"),
                                    "--data-dir", str(tmp_path / "identity")], cwd=ROOT, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    assert client.get("/health").status_code == 200
                    return
                except OSError:
                    time.sleep(0.05)
            pytest.fail((tmp_path / "server.log").read_text())
        finally:
            process.terminate()
            process.wait(timeout=10)
