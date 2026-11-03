"""Native launcher dependency refresh; deliberately uses only the Python standard library."""
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def sync_dependencies(root=ROOT):
    lock = root / "requirements.lock"
    if not lock.is_file():
        raise OSError("requirements.lock is missing; restore the complete server checkout")
    requirements = [line.strip().split("==", 1) for line in lock.read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    digest = hashlib.sha256(lock.read_bytes() + str(sys.version_info[:2]).encode()).hexdigest()
    state = Path(sys.prefix) / ".carriex-runtime.json"
    try:
        saved = json.loads(state.read_text())
    except (OSError, ValueError):
        saved = {}
    if not isinstance(saved, dict):
        saved = {}
    installed = {}
    for name, version in requirements:
        try:
            installed[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            installed[name] = None
    # Respect later manual upgrades once this lock has been applied, but repair removals.
    present = all(installed.values())
    exact = all(installed[name] == version for name, version in requirements)
    if not (present and (saved.get("lock") == digest or exact)):
        print("Refreshing Carriex runtime dependencies for this update...", flush=True)
        completed = subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "-r", str(lock)])
        if completed.returncode:
            raise OSError("Dependency update failed. Check internet access and rerun the launcher. "
                          "Manual repair: python -m pip install -r requirements.txt")
        for name, version in requirements:
            if metadata.version(name) != version:
                raise OSError(f"Runtime dependency {name} did not install correctly; rerun pip in this virtual environment")
    if saved.get("lock") != digest:
        try:
            state.write_text(json.dumps({"lock": digest}), encoding="utf-8")
        except OSError:
            # Dependency verification still succeeded; a read-only venv need not stop serving.
            pass


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if sys.version_info < (3, 11):
            raise OSError("Carriex requires Python 3.11 or newer; recreate .venv with a supported Python")
        info_only = any(flag in argv for flag in ("--help", "-h", "--check-config", "--pair-only", "--init-config", "--migrate-config"))
        if not info_only:
            sync_dependencies()
        command = [sys.executable, "-m", "src.pairing", *argv]
        if os.name != "nt":
            os.chdir(ROOT)
            os.execv(sys.executable, command)
        return subprocess.call(command, cwd=ROOT)
    except (OSError, metadata.PackageNotFoundError) as error:
        print(f"Unable to start Carriex: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
