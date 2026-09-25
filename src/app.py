import os

from flask import Flask
from flask_sock import Sock
from werkzeug.middleware.proxy_fix import ProxyFix

from src.auth import register_auth

from src.routes import register_routes
from src.store import MessageStore
from src.websocket import register_websocket


def create_app(config=None):
    app = Flask(__name__)
    app.config.setdefault("TESTING", False)
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
    app.config["ALLOW_INSECURE_HTTP"] = os.environ.get("CARRIEX_ALLOW_INSECURE_HTTP") == "1"
    app.config["AUTH_ORIGIN"] = os.environ.get("CARRIEX_AUTH_ORIGIN", "").rstrip("/")
    if config:
        app.config.update(config)
    data_dir = app.config.get("MESSAGE_DATA_DIR") or os.environ.get("CARRIEX_DATA_DIR", ".carriex-server")
    app.extensions["message_store"] = MessageStore(
        os.path.join(data_dir, "messages.sqlite3"),
        app.config.get("MESSAGE_TTL_SECONDS", os.environ.get("CARRIEX_MESSAGE_TTL_SECONDS", 30 * 24 * 3600)),
    )
    # Enable only behind a trusted proxy that overwrites X-Forwarded-Proto;
    # the backend port must not be publicly reachable in this mode.
    if os.environ.get("CARRIEX_TRUST_PROXY") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=0, x_proto=1, x_host=0, x_port=0, x_prefix=0)

    app.config.setdefault("SOCK_SERVER_OPTIONS", {"ping_interval": 25, "max_message_size": 2 * 1024 * 1024})
    sock = Sock(app)
    register_auth(app)
    register_routes(app)
    register_websocket(sock)

    return app


app = create_app()
