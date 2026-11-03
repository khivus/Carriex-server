"""Refresh .env documentation/layout without executing values or replacing identity data."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import os
from pathlib import Path
import re
import secrets
import sys

from dotenv.parser import parse_stream


MARKER = "# Carriex settings template SHA256: "
EXTRAS = "# PRESERVED ADVANCED SETTINGS AND PERSONAL NOTES"


@dataclass(frozen=True)
class Migration:
    changed: bool = False
    backup: Path | None = None


def template_path():
    checkout = Path(__file__).resolve().parents[1] / ".env.example"
    if checkout.is_file():
        return checkout
    installed = Path(sys.prefix) / "share/carriex-server/.env.example"
    if installed.is_file():
        return installed
    raise OSError("Settings template is unavailable; reinstall the server package")


def bindings(text):
    result = list(parse_stream(io.StringIO(text)))
    names = set()
    for item in result:
        if item.error:
            raise ValueError(f"Invalid .env syntax at line {item.original.line}; config was not rewritten")
        if item.key:
            if item.key in names:
                raise ValueError(f"Duplicate setting {item.key}; config was not rewritten")
            names.add(item.key)
    return result


def migrate_config(path, *, initial=None, create=False, template=None):
    """Read actual file values only; shell and CLI overrides never leak into the file."""
    path = Path(path).resolve()
    exists = path.exists()
    if not exists and not create:
        return Migration()
    original = path.read_bytes() if exists else b""
    text = original.decode("utf-8-sig")
    source = (Path(template) if template else template_path()).read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    sections = [line for line in source.splitlines() if re.match(r"# \d+ \| ", line)]
    parsed = bindings(text)
    if not initial and MARKER + digest in text and all(section in text for section in sections):
        return Migration()

    newline = "\r\n" if b"\r\n" in original else "\n"
    values = {item.key: item.original.string.lstrip("\r\n").replace("\r\n", "\n").rstrip("\n")
              for item in parsed if item.key}
    for key, value in (initial or {}).items():
        if key not in values:
            escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
            values[key] = f"{key}='{escaped}'"

    rendered = []
    for line in source.splitlines():
        match = re.match(r"^(?:#\s*)?([A-Z][A-Z0-9_]+)\s*=", line)
        if match and match[1] in values:
            rendered.append(values.pop(match[1]))
        elif match and not line.startswith("#"):
            # Example address/name must never override a saved identity or shell settings.
            rendered.append("# " + line)
        else:
            rendered.append(line)

    template_comments = {line.strip() for line in source.splitlines() if line.lstrip().startswith("#")}
    notes = []
    for item in parsed:
        if item.key:
            continue
        for line in item.original.string.splitlines():
            stripped = line.strip()
            if not stripped or stripped in template_comments or stripped.startswith(MARKER) or stripped == EXTRAS:
                continue
            if re.match(r"# (?:Server version:|\d+ \| )", stripped) or re.fullmatch(r"# [=]+", stripped):
                continue
            if stripped not in notes:
                notes.append(stripped)
    if values or notes:
        rendered += ["", "", "# ==============================================================================", EXTRAS,
                     "# ==============================================================================", *notes, *values.values()]
    result = (MARKER + digest + "\n" + "\n".join(rendered).rstrip() + "\n").replace("\n", newline).encode("utf-8")
    if original.startswith(b"\xef\xbb\xbf"):
        result = b"\xef\xbb\xbf" + result
    if result == original:
        return Migration()
    if exists and not path.stat().st_mode & 0o222:
        raise PermissionError("Settings file is read-only; leaving its values unchanged")

    path.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if exists:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        backup = path.with_name(path.name + ".backup-" + stamp + "-" + secrets.token_hex(3))
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        mode = path.stat().st_mode & 0o777 if exists else 0o600
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(result)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        if (path.read_bytes() if path.exists() else b"") != original:
            raise OSError("Settings changed during migration; retry startup to preserve the newer edits")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return Migration(True, backup)
