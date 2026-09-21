"""Read explicit .env settings without executing shell code or searching parent folders."""
import os
from pathlib import Path

from dotenv.parser import parse_stream


KEYS = {
    "CARRIEX_HOST", "CARRIEX_PORT", "CARRIEX_SERVER_NAME", "CARRIEX_BIND",
    "CARRIEX_LISTEN_PORT", "CARRIEX_IDENTITY_DIR", "CARRIEX_PUBLIC_URL", "CARRIEX_TLS_PORT",
}


def read_config(path):
    values = {}
    path = Path(path)
    if path.exists():
        with path.open(encoding="utf-8-sig") as stream:
            for item in parse_stream(stream):
                if item.error:
                    raise ValueError(f"Invalid .env syntax at line {item.original.line}")
                if item.key in KEYS:
                    if item.key in values:
                        raise ValueError(f"Duplicate setting {item.key} in {path}")
                    if item.value is None:
                        raise ValueError(f"{item.key} needs an =value")
                    values[item.key] = item.value
                elif item.key and item.key.startswith("CARRIEX_") and item.key not in {
                    "CARRIEX_TRUST_PROXY", "CARRIEX_AUTH_ORIGIN", "CARRIEX_ALLOW_INSECURE_HTTP",
                }:
                    raise ValueError(f"Unknown setting {item.key} in {path}")
    # Shell/container settings override file settings. Values are literal, not expanded.
    values.update({key: os.environ[key] for key in KEYS if key in os.environ})
    return values


def port_number(value, label):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a number between 1 and 65535") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"{label} must be between 1 and 65535")
    return port


def host_address(host, port):
    if not host or any(c in host for c in "/@?#\\") or any(c.isspace() for c in host):
        raise ValueError("CARRIEX_HOST must be an IP or hostname without https://, a port, or a path")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"https://{host}:{port}"
