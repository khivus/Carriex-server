"""Read explicit .env settings without executing shell code or searching parent folders."""
import os
from pathlib import Path

from dotenv.parser import parse_stream
from src.security import DEFAULTS


KEYS = {
    "CARRIEX_HOST", "CARRIEX_PORT", "CARRIEX_SERVER_NAME", "CARRIEX_BIND",
    "CARRIEX_LISTEN_PORT", "CARRIEX_IDENTITY_DIR", "CARRIEX_PAIRING_EXPORT_DIR",
    "CARRIEX_PUBLIC_URL", "CARRIEX_TLS_PORT",
    "CARRIEX_MESSAGE_TTL_SECONDS", "CARRIEX_STATISTICS", "CARRIEX_STATISTICS_RETENTION_DAYS",
    "CARRIEX_REGISTRATION_MODE", "CARRIEX_CONNECTION_LIMIT", "CARRIEX_CONNECTIONS_PER_IP", "CARRIEX_REQUEST_TIMEOUT", "CARRIEX_MAX_DATABASE_BYTES",
}
KEYS.update("CARRIEX_" + name for name in DEFAULTS)


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
                    "CARRIEX_TRUST_PROXY", "CARRIEX_AUTH_ORIGIN", "CARRIEX_ALLOW_INSECURE_HTTP", "CARRIEX_PROXY_NETWORKS",
                }:
                    raise ValueError(f"Unknown setting {item.key} in {path}")
    # Shell/container settings override file settings. Values are literal, not expanded.
    values.update({key: os.environ[key] for key in KEYS if key in os.environ})
    return values


def validate_runtime_settings(values):
    """Fail on invalid limits before writing config, identity files or databases."""
    def number(key, default):
        try:
            return int(values.get(key, default))
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a whole number") from None
    for name, default in DEFAULTS.items():
        key = "CARRIEX_" + name
        if number(key, default) <= 0:
            raise ValueError(f"{key} must be a positive whole number")
    if values.get("CARRIEX_REGISTRATION_MODE", "open") not in {"open", "approved"}:
        raise ValueError("CARRIEX_REGISTRATION_MODE must be open or approved")
    if number("CARRIEX_CONNECTION_LIMIT", 128) < 16:
        raise ValueError("CARRIEX_CONNECTION_LIMIT must be at least 16")
    if number("CARRIEX_CONNECTIONS_PER_IP", 32) <= 0:
        raise ValueError("CARRIEX_CONNECTIONS_PER_IP must be positive")
    if not 1 <= number("CARRIEX_REQUEST_TIMEOUT", 15) <= 120:
        raise ValueError("CARRIEX_REQUEST_TIMEOUT must be between 1 and 120 seconds")
    if number("CARRIEX_MAX_DATABASE_BYTES", 1073741824) < 16 * 1024 * 1024:
        raise ValueError("CARRIEX_MAX_DATABASE_BYTES must be at least 16777216 (16 MiB)")
    if number("CARRIEX_MESSAGE_TTL_SECONDS", 2592000) <= 0:
        raise ValueError("CARRIEX_MESSAGE_TTL_SECONDS must be positive")


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
