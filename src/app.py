from flask import Flask
from flask_sock import Sock

from src.routes import register_routes
from src.websocket import register_websocket


def create_app():
    app = Flask(__name__)
    app.config.setdefault("TESTING", False)

    sock = Sock(app)
    register_routes(app)
    register_websocket(sock)

    return app


app = create_app()
