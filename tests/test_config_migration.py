"""Filesystem/config upgrades; no private server state or network targets."""
import io
from pathlib import Path

from dotenv.parser import parse_stream
import pytest

from src.config_migration import migrate_config, template_path


def settings(text):
    return {item.key: item.value for item in parse_stream(io.StringIO(text)) if item.key}


def test_flat_file_regains_categories_without_losing_values_or_personal_comments(tmp_path):
    path = tmp_path / ".env"
    original = "# My home relay\nCARRIEX_HOST = 'home.example' # keep this note\nCARRIEX_PORT=443\nCARRIEX_SERVER_NAME='My # relay'\nCUSTOM_VALUE='literal ${HOME}'\n"
    path.write_text(original)
    result = migrate_config(path)
    updated = path.read_text()
    assert result.changed and result.backup.read_text() == original
    assert settings(updated) == settings(original)
    assert "# 01 | CONNECTION AND SERVER NAME" in updated and "# 08 | INTERNET EXPOSURE" in updated
    assert "\n\n# ===" in updated and "# My home relay" in updated
    assert "CARRIEX_HOST = 'home.example' # keep this note" in updated
    assert "# CARRIEX_REGISTRATION_MODE=approved" in updated
    assert not migrate_config(path).changed
    assert len(list(tmp_path.glob(".env.backup-*"))) == 1


def test_legacy_url_never_gets_overridden_by_example_host_or_port(tmp_path):
    path = tmp_path / ".env"
    old = "CARRIEX_PUBLIC_URL=https://legacy.example\nCARRIEX_TLS_PORT=9443\nHOST=127.0.0.1\nPORT=5000\n"
    path.write_text(old)
    migrate_config(path)
    assert settings(path.read_text()) == settings(old)
    assert "CARRIEX_HOST" not in settings(path.read_text())
    assert "CARRIEX_PORT" not in settings(path.read_text())


def test_next_template_update_adds_only_commented_options_and_backs_up_again(tmp_path):
    path = tmp_path / ".env"
    path.write_text("CARRIEX_HOST=localhost\n")
    first = migrate_config(path)
    prior = path.read_bytes()
    template = tmp_path / "template"
    template.write_text(template_path().read_text() + "\n# CARRIEX_FUTURE_OPTION=42\n")
    second = migrate_config(path, template=template)
    assert first.changed and second.changed and second.backup.read_bytes() == prior
    assert "# CARRIEX_FUTURE_OPTION=42" in path.read_text()
    assert settings(path.read_text()) == {"CARRIEX_HOST": "localhost"}
    assert not migrate_config(path, template=template).changed


def test_environment_overrides_are_not_persisted(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text("CARRIEX_HOST=saved.example\n")
    monkeypatch.setenv("CARRIEX_HOST", "temporary.example")
    migrate_config(path)
    assert settings(path.read_text())["CARRIEX_HOST"] == "saved.example"


@pytest.mark.parametrize("original", ["CARRIEX_HOST='unfinished", "CARRIEX_HOST=a\nCARRIEX_HOST=b\n"])
def test_invalid_or_duplicate_values_are_never_rewritten(tmp_path, original):
    path = tmp_path / ".env"
    path.write_text(original)
    with pytest.raises(ValueError):
        migrate_config(path)
    assert path.read_text() == original
    assert not list(tmp_path.glob(".env.backup-*"))


def test_migration_preserves_crlf_bom_and_file_mode(tmp_path):
    path = tmp_path / ".env"
    original = b"\xef\xbb\xbfCARRIEX_HOST=localhost\r\nCARRIEX_PORT=443\r\n"
    path.write_bytes(original)
    mode = path.stat().st_mode & 0o777
    migrated = migrate_config(path)
    output = path.read_bytes()
    assert output.startswith(b"\xef\xbb\xbf")
    assert b"\n" not in output.replace(b"\r\n", b"")
    assert migrated.backup.read_bytes() == original
    assert path.stat().st_mode & 0o777 == mode


def test_read_only_file_does_not_get_replaced(tmp_path):
    path = tmp_path / ".env"
    path.write_text("CARRIEX_HOST=localhost\n")
    path.chmod(0o444)
    try:
        with pytest.raises(PermissionError):
            migrate_config(path)
        assert path.read_text() == "CARRIEX_HOST=localhost\n"
    finally:
        path.chmod(0o600)


def test_simultaneous_user_edit_is_not_overwritten(tmp_path, monkeypatch):
    path = (tmp_path / ".env").resolve()
    path.write_text("CARRIEX_HOST=first.example\n")
    original_read = Path.read_bytes
    calls = 0
    def read(candidate):
        nonlocal calls
        if candidate == path:
            calls += 1
            if calls == 2:
                path.write_text("CARRIEX_HOST=user-edited.example\n")
        return original_read(candidate)
    monkeypatch.setattr(Path, "read_bytes", read)
    with pytest.raises(OSError, match="changed during migration"):
        migrate_config(path)
    assert path.read_text() == "CARRIEX_HOST=user-edited.example\n"


def test_new_template_creation_never_activates_an_example_address(tmp_path):
    path = tmp_path / ".env"
    assert not migrate_config(path).changed
    result = migrate_config(path, create=True)
    assert result.changed and result.backup is None
    assert settings(path.read_text()) == {}
