"""Exercise config migration through the public CLI in isolated subprocesses."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def invoke(tmp_path, *args, module="src.pairing", code=None, success=True):
    env = {key: value for key, value in os.environ.items() if not key.startswith("CARRIEX_")}
    command = [sys.executable, "-c", code] if code else [sys.executable, "-m", module]
    command += ["--config", str(tmp_path / "server.env"), "--data-dir", str(tmp_path / "identity"), *args]
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert (result.returncode == 0) == success, result.stdout + result.stderr
    return result


def test_launcher_migrates_once_and_preserves_identity(tmp_path):
    config = tmp_path / "server.env"
    original = b"# My home server\nCARRIEX_HOST=localhost\nCARRIEX_PORT=18443\nCARRIEX_SERVER_NAME='Home'\n"
    config.write_bytes(original)
    result = invoke(tmp_path, "--pair-only", module="src.bootstrap")
    assert "Settings template updated" in result.stdout
    backups = list(tmp_path.glob("server.env.backup-*"))
    assert len(backups) == 1 and backups[0].read_bytes() == original
    migrated = config.read_bytes()
    private = tmp_path / "identity/server-key.pem"
    fingerprint = hashlib.sha256(private.read_bytes()).digest()
    result = invoke(tmp_path, "--pair-only", module="src.bootstrap")
    assert "Settings template updated" not in result.stdout
    assert config.read_bytes() == migrated
    assert len(list(tmp_path.glob("server.env.backup-*"))) == 1
    assert hashlib.sha256(private.read_bytes()).digest() == fingerprint


def test_launcher_check_is_read_only(tmp_path):
    config = tmp_path / "server.env"
    original = b"CARRIEX_HOST=localhost\nCARRIEX_PORT=8443\n"
    config.write_bytes(original)
    invoke(tmp_path, "--check-config", module="src.bootstrap")
    assert config.read_bytes() == original
    assert not list(tmp_path.glob("server.env.backup-*"))
    assert not (tmp_path / "identity").exists()


def test_explicit_migration_creates_template_without_address_or_identity(tmp_path):
    invoke(tmp_path, "--migrate-config", module="src.bootstrap")
    text = (tmp_path / "server.env").read_text()
    assert "# 01 |" in text and "# 08 |" in text
    assert "\nCARRIEX_HOST=" not in text
    assert not (tmp_path / "identity").exists()


@pytest.mark.parametrize("setting", [
    "CARRIEX_CONNECTION_LIMIT=1", "CARRIEX_CONNECTIONS_PER_IP=0",
    "CARRIEX_REQUEST_TIMEOUT=121", "CARRIEX_MAX_DATABASE_BYTES=1",
    "CARRIEX_SENDER_PENDING_LIMIT=0", "CARRIEX_REGISTRATION_MODE=typo",
])
def test_bad_limits_fail_before_migration_or_identity(tmp_path, setting):
    config = tmp_path / "server.env"
    original = "CARRIEX_HOST=localhost\n" + setting + "\n"
    config.write_text(original)
    result = invoke(tmp_path, "--pair-only", success=False)
    assert setting.split("=", 1)[0] in result.stderr
    assert config.read_text() == original
    assert not list(tmp_path.glob("server.env.backup-*"))
    assert not (tmp_path / "identity").exists()


def test_missing_gevent_reports_repair_before_modifying_files(tmp_path):
    config = tmp_path / "server.env"
    original = b"CARRIEX_HOST=localhost\n"
    config.write_bytes(original)
    code = """
import importlib.abc, runpy, sys
class BlockGevent(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'gevent' or fullname.startswith('gevent.'):
            raise ImportError('Simulated pre-update environment')
sys.meta_path.insert(0, BlockGevent())
runpy.run_module('src.pairing', run_name='__main__')
"""
    result = invoke(tmp_path, code=code, success=False)
    assert "needs gevent" in result.stderr and "pip install -r requirements.txt" in result.stderr
    assert "Traceback" not in result.stderr
    assert config.read_bytes() == original
    assert not (tmp_path / "identity").exists()


@pytest.mark.parametrize("readonly", [True, False])
def test_readonly_or_optout_config_does_not_prevent_pairing(tmp_path, readonly):
    config = tmp_path / "server.env"
    original = b"CARRIEX_HOST=localhost\n"
    config.write_bytes(original)
    mode = config.stat().st_mode
    try:
        if readonly:
            config.chmod(0o444)
        result = invoke(tmp_path, "--pair-only", *([] if readonly else ["--no-migrate-config"]))
        assert ("Settings layout was not migrated" in result.stderr) == readonly
        assert config.read_bytes() == original
        assert not list(tmp_path.glob("server.env.backup-*"))
        assert (tmp_path / "identity/pairing.json").is_file()
    finally:
        config.chmod(mode)
