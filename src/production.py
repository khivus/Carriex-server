"""Bounded production HTTP/TLS listener shared by Windows, Linux and Docker."""
from gevent import monkey
monkey.patch_all()

import argparse
from collections import Counter
import os
import ssl
import time

from gevent import Timeout
from gevent.pool import Pool
from gevent.pywsgi import WSGIHandler, WSGIServer
from werkzeug.exceptions import RequestTimeout

from src.security import RateLimiter


class DeadlineInput:
    def __init__(self, stream, deadline):
        self.stream, self.deadline = stream, deadline

    def _read(self, method, *args):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise RequestTimeout("Request body deadline exceeded")
        with Timeout(remaining, RequestTimeout("Request body deadline exceeded")):
            return getattr(self.stream, method)(*args)

    def read(self, *args):
        return self._read("read", *args)

    def readline(self, *args):
        return self._read("readline", *args)

    def readlines(self, *args):
        return self._read("readlines", *args)

    def __getattr__(self, name):
        return getattr(self.stream, name)


class DeadlineHandler(WSGIHandler):
    def handle_one_request(self):
        self.header_deadline = Timeout(self.server.request_timeout, OSError("Request header deadline exceeded"))
        self.header_deadline.start()
        try:
            return super().handle_one_request()
        finally:
            self.header_deadline.cancel()

    def get_environ(self):
        self.header_deadline.cancel()
        environ = super().get_environ()
        environ["wsgi.input"] = DeadlineInput(environ["wsgi.input"], time.monotonic() + self.server.request_timeout)
        return environ


class RelayServer(WSGIServer):
    handler_class = DeadlineHandler

    def __init__(self, *args, request_timeout=15, **kwargs):
        self.request_timeout = request_timeout
        self.source_limit = int(os.environ.get("CARRIEX_CONNECTIONS_PER_IP", 32))
        if self.source_limit <= 0:
            raise ValueError("CARRIEX_CONNECTIONS_PER_IP must be positive")
        self.sources = Counter()
        self.connection_budgets = RateLimiter()
        super().__init__(*args, **kwargs)

    def do_read(self):
        accepted = super().do_read()
        if not accepted:
            return accepted
        sock, address = accepted
        source = address[0]
        if (self.sources[source] >= self.source_limit or self.connection_budgets.consume("source", source, 180) or
            self.connection_budgets.consume("global", "all", 1200)):
            sock.close()
            return None
        self.sources[source] += 1
        return sock, address

    def do_close(self, sock, address):
        self.sources[address[0]] -= 1
        if self.sources[address[0]] <= 0:
            del self.sources[address[0]]
        super().do_close(sock, address)

    def wrap_socket_and_handle(self, client_socket, address):
        client_socket.settimeout(5)
        # The TLS handshake has an absolute deadline, even with trickled bytes.
        with Timeout(5, OSError("TLS handshake deadline exceeded")):
            secured = self.wrap_socket(client_socket, **self.ssl_args)
        try:
            return self.handle(secured, address)
        finally:
            secured.close()

    def handle(self, sock, address):
        sock.settimeout(self.request_timeout)
        return super().handle(sock, address)


def serve(app, host, port, certificate=None, key=None):
    options = {}
    if certificate:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, key)
        options["ssl_context"] = context
    maximum = int(os.environ.get("CARRIEX_CONNECTION_LIMIT", 128))
    timeout = int(os.environ.get("CARRIEX_REQUEST_TIMEOUT", 15))
    if maximum < 16 or not 1 <= timeout <= 120:
        raise ValueError("Connection limit must be at least 16; request timeout must be 1-120 seconds")
    # Access logs omit URLs/headers; application diagnostics must not log tokens.
    server = RelayServer((host, port), app, spawn=Pool(maximum), backlog=128,
                         request_timeout=timeout, log=None, **options)
    print(f"Carriex production listener on {host}:{port} (maximum {maximum} connections)", flush=True)
    server.serve_forever()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--certfile")
    parser.add_argument("--keyfile")
    args = parser.parse_args(argv)
    if bool(args.certfile) != bool(args.keyfile):
        parser.error("Provide both --certfile and --keyfile")
    from src.app import app
    serve(app, args.host, args.port, args.certfile, args.keyfile)


if __name__ == "__main__":
    main()
