"""Bounded ingress budgets, trusted proxy handling and JSON parsing."""
from collections import OrderedDict
import ipaddress
import json
import math
import os
from threading import Lock
import time

from flask import Request, current_app, g, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix


DEFAULTS = {
    "HTTP_IP_RATE": 600, "HTTP_GLOBAL_RATE": 6000,
    "AUTH_IP_RATE": 60, "AUTH_GLOBAL_RATE": 600,
    "SEND_DEVICE_RATE": 180, "SEND_IP_RATE": 600,
    "WS_DEVICE_LIMIT": 2, "WS_IP_LIMIT": 20, "WS_GLOBAL_LIMIT": 64,
    "WS_MESSAGE_RATE": 180, "WS_BYTE_RATE": 8 * 1024 * 1024,
    "WS_PENDING_LIMIT": 16, "WS_PENDING_BYTES": 2 * 1024 * 1024,
    "AUTH_DEVICE_SESSIONS": 4, "AUTH_DEVICE_CHALLENGES": 3,
    "AUTH_CAPACITY": 10000,
    "ENROLL_IP_HOURLY": 30, "ENROLL_GLOBAL_HOURLY": 120,
    "SENDER_PENDING_LIMIT": 4000, "SENDER_STORAGE_BYTES": 8 * 1024 * 1024,
    "GROUP_INVITATION_LIMIT": 16, "GROUP_INVITATIONS_HOURLY": 60,
    "GROUPS_PER_ADMIN": 128, "GROUP_EVENTS_PER_ADMIN": 8192,
    "DIRECTORY_IDLE_DAYS": 90,
}


def configure(app):
    app.config.setdefault("RATE_LIMIT_ENABLED", True)
    app.config.setdefault("REGISTRATION_MODE", os.environ.get("CARRIEX_REGISTRATION_MODE", "open"))
    if app.config["REGISTRATION_MODE"] not in {"open", "approved"}:
        raise ValueError("CARRIEX_REGISTRATION_MODE must be open or approved")
    for name, default in DEFAULTS.items():
        app.config.setdefault(name, int(os.environ.get("CARRIEX_" + name, default)))
        if type(app.config[name]) is not int or app.config[name] <= 0:
            raise ValueError(name + " must be a positive whole number")
    app.extensions["ingress_limits"] = RateLimiter()


class RateLimiter:
    """Token buckets have bounded cardinality and expire after idle time."""
    def __init__(self, capacity=10000):
        self.lock = Lock()
        self.buckets = OrderedDict()
        self.capacity = capacity

    def consume(self, name, subject, maximum, cost=1, period=60):
        now = time.monotonic()
        key = (name, subject)
        with self.lock:
            while self.buckets and next(iter(self.buckets.values()))[1] < now - 2 * period:
                self.buckets.popitem(last=False)
            previous = self.buckets.get(key)
            if previous is None and len(self.buckets) >= self.capacity:
                return max(1, math.ceil(period))
            available, last = previous or (maximum, now)
            available = min(maximum, available + (now - last) * maximum / period)
            retry = 0 if cost <= available else max(1, math.ceil((cost - available) * period / maximum))
            self.buckets[key] = (available - cost if not retry else available, now)
            self.buckets.move_to_end(key)
            return retry


def budget(name, subject, maximum, cost=1, period=60):
    if not current_app.config["RATE_LIMIT_ENABLED"]:
        return 0
    return current_app.extensions["ingress_limits"].consume(name, subject, maximum, cost, period)


def throttled(seconds, message="Too many requests; retry later"):
    response = jsonify(error=message, code="rate_limited", retry_after=seconds)
    response.status_code = 429
    response.headers["Retry-After"] = str(seconds)
    return response


class TrustedProxy:
    def __init__(self, app, networks):
        self.app = app
        self.fixed = ProxyFix(app, x_for=1, x_proto=1, x_host=0, x_port=0, x_prefix=0)
        self.networks = [ipaddress.ip_network(value.strip()) for value in networks.split(",") if value.strip()]
        if not self.networks or any(value.prefixlen == 0 for value in self.networks):
            raise ValueError("Explicit trusted proxy networks are required; wildcard networks are unsafe")

    def __call__(self, environ, start_response):
        try:
            source = ipaddress.ip_address(environ.get("REMOTE_ADDR", ""))
        except ValueError:
            source = None
        trusted = source is not None and any(source in network for network in self.networks)
        if trusted:
            return self.fixed(environ, start_response)
        # Direct requests never acquire security properties from forwarding headers.
        return self.app(environ, start_response)


def checked_json(value):
    """Bound nesting before calling the recursive CPython JSON decoder."""
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    depth = 0
    quoted = escaped = False
    for char in value:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 64:
                raise ValueError("JSON nesting exceeds 64 levels")
        elif char in "]}":
            depth -= 1
    return json.loads(value)


class RelayRequest(Request):
    def get_json(self, force=False, silent=False, cache=True):
        if not (force or self.is_json):
            return super().get_json(force=force, silent=silent, cache=cache)
        try:
            # Decode once; Flask still owns body-size checks and HTTP errors.
            if cache and hasattr(self, "_relay_json_value"):
                return self._relay_json_value
            value = checked_json(self.get_data(cache=True))
            if cache:
                self._relay_json_value = value
            return value
        except (ValueError, UnicodeError, RecursionError):
            if silent:
                return None
            from werkzeug.exceptions import BadRequest
            raise BadRequest("Invalid or excessively nested JSON") from None


def register_ingress(app):
    @app.before_request
    def ingress():
        source = request.remote_addr or "unknown"
        for name, subject in (("HTTP_IP_RATE", source), ("HTTP_GLOBAL_RATE", "all")):
            retry = budget(name, subject, app.config[name])
            if retry:
                g.rate_limited = True
                return throttled(retry)
        if request.endpoint in {"auth.challenge", "auth.verify"}:
            for name, subject in (("AUTH_IP_RATE", source), ("AUTH_GLOBAL_RATE", "all")):
                retry = budget(name, subject, app.config[name])
                if retry:
                    return throttled(retry)
            if request.content_length is not None and request.content_length > 4096:
                return jsonify(error="Authentication body exceeds 4 KiB"), 413

    @app.after_request
    def private_responses(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
