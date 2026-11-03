"""Native dependency refresh decisions; never install packages during these tests."""
import json
from types import SimpleNamespace

import pytest

from src import bootstrap


def setup(tmp_path, monkeypatch, installed):
    (tmp_path / "requirements.lock").write_text("# runtime\ngevent==1.2.3\nflask==4.5.6\n")
    monkeypatch.setattr(bootstrap.sys, "prefix", str(tmp_path))
    def version(name):
        if name not in installed:
            raise bootstrap.metadata.PackageNotFoundError(name)
        return installed[name]
    monkeypatch.setattr(bootstrap.metadata, "version", version)


def test_missing_runtime_is_refreshed_and_subsequent_start_is_offline(tmp_path, monkeypatch):
    installed = {"flask": "4.5.6"}
    setup(tmp_path, monkeypatch, installed)
    calls = []
    def install(command):
        calls.append(command)
        installed["gevent"] = "1.2.3"
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(bootstrap.subprocess, "run", install)
    bootstrap.sync_dependencies(tmp_path)
    bootstrap.sync_dependencies(tmp_path)
    assert len(calls) == 1
    assert calls[0][:4] == [bootstrap.sys.executable, "-m", "pip", "install"]
    assert json.loads((tmp_path / ".carriex-runtime.json").read_text())["lock"]


def test_changed_lock_refreshes_runtime_but_preserves_later_manual_upgrades(tmp_path, monkeypatch):
    installed = {"flask": "4.5.6", "gevent": "1.2.3"}
    setup(tmp_path, monkeypatch, installed)
    calls = []
    def install(command):
        calls.append(command); installed["gevent"] = "2.0.0"
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(bootstrap.subprocess, "run", install)
    bootstrap.sync_dependencies(tmp_path)
    installed["gevent"] = "1.2.4"
    bootstrap.sync_dependencies(tmp_path)
    assert not calls
    (tmp_path / "requirements.lock").write_text("gevent==2.0.0\nflask==4.5.6\n")
    bootstrap.sync_dependencies(tmp_path)
    assert len(calls) == 1 and installed["gevent"] == "2.0.0"


def test_failed_download_does_not_mark_dependencies_current(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch, {})
    monkeypatch.setattr(bootstrap.subprocess, "run", lambda command: SimpleNamespace(returncode=1))
    with pytest.raises(OSError, match="Dependency update failed"):
        bootstrap.sync_dependencies(tmp_path)
    assert not (tmp_path / ".carriex-runtime.json").exists()
