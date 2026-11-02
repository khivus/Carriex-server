"""Record installed production dependencies after tests and an advisory audit."""
from collections import deque
from importlib.metadata import distribution
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def main():
    pending = deque([("carriex-server", frozenset({"server"}))])
    visited, packages = set(), {}
    while pending:
        name, extras = pending.popleft()
        identity = canonicalize_name(name), extras
        if identity in visited:
            continue
        visited.add(identity)
        installed = distribution(name)
        if canonicalize_name(name) != "carriex-server":
            packages[canonicalize_name(installed.metadata["Name"])] = installed.version
        for value in installed.requires or []:
            requirement = Requirement(value)
            if requirement.marker is None or any(requirement.marker.evaluate({"extra": extra}) for extra in {"", *extras}):
                pending.append((requirement.name, frozenset(requirement.extras)))
    text = "# Production CPython dependencies; regenerate after tests and pip-audit.\n"
    text += "# Windows-only pure-Python dependencies are harmless on Linux/macOS.\n"
    text += "\n".join(f"{name}=={version}" for name, version in sorted(packages.items())) + "\n"
    (Path(__file__).resolve().parents[1] / "requirements.lock").write_text(text, encoding="utf-8")
    print(f"Recorded {len(packages)} production dependency versions")


if __name__ == "__main__":
    main()
