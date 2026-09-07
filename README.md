# Carriex Server

A Flask and Flask-Sock server that relays opaque encrypted message payloads
over HTTP and WebSockets. It does not encrypt or decrypt payloads itself.

## Local development

Requires Python 3.11 or newer.

```sh
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell instead:
# .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m flask --app src.app:app run --host 127.0.0.1 --port 5000
```

`python main.py` is also a development launcher; it enables debug mode and
binds to all interfaces. Use Docker for the Gunicorn runtime.

## Docker

```sh
docker compose up --build -d
docker compose logs -f server
docker compose down
```

The default address is `http://127.0.0.1:5000`. Optionally copy `.env.example`
to `.env` to change the published host or port. Compose reads this file
automatically. The image runs as a non-root user and checks `/health`.

Without Compose:

```sh
docker build -t carriex-server .
docker run --rm -p 127.0.0.1:5000:5000 carriex-server
```

The container uses one Gunicorn worker with 100 threads. Active WebSocket
connections occupy threads, so leave capacity for HTTP requests. Do not increase
workers or scale replicas: queues and connections are process-local.
Queued messages disappear on restart; there is no persistent storage.

## API

| Endpoint | Behavior |
| --- | --- |
| `GET /health` | Status, project version, connected users and clients |
| `POST /send` | Accepts `sender`, `recipient`, `ciphertext`; delivers or queues |
| `GET /messages/<user_id>` | Retrieves and removes queued messages |
| `WS /ws/<user_id>` | Delivers queued messages on connect and live messages |

```sh
curl -X POST http://127.0.0.1:5000/send -H "Content-Type: application/json" -d '{"sender":"alice","recipient":"bob","ciphertext":"encrypted-payload"}'
curl http://127.0.0.1:5000/messages/bob
```

On Windows, use `curl.exe` if `curl` is a PowerShell alias.

WebSocket clients send `{"type":"health"}` or
`{"type":"send","recipient":"bob","ciphertext":"encrypted-payload"}`.
The connection's user ID supplies the sender. Replies use `health`, `sent`, or
`error`; deliveries have the shape
`{"type":"message","message":{"from":"alice","ciphertext":"encrypted-payload","timestamp":"..."}}`.

User IDs are not authenticated, and message retrieval is destructive. Before
exposing this service to untrusted networks, add authentication, authorization,
TLS termination, and resource limits. See [SECURITY.md](SECURITY.md).

## Checks and packaging

```sh
python -m pytest -q
python -m ruff check .
python -m build
```

See [tests/README.md](tests/README.md) for integration test details. Dependencies
are defined in `pyproject.toml`; `requirements.txt` installs the development
extra. Dependency ranges are not a lockfile: builds may resolve newer compatible
versions.

## Versioning

`src/_version.py` is the single version source, starting at `0.1.0`. Setuptools
reads it for package metadata; Python exposes `src.__version__`, and `/health`
reports it. Follow Semantic Versioning (`MAJOR.MINOR.PATCH`). During `0.x`,
minor releases may change the API; patches should remain compatible.

For a release, update that file and move changelog entries from `Unreleased` to
a dated version section. Run checks, merge, then create a matching Git tag such
as `v0.1.0` and a GitHub release using the changelog. CI verifies version tags
match package metadata. Nothing is automatically published.

See [CONTRIBUTING.md](CONTRIBUTING.md). No license has been selected yet;
this repository does not currently grant an open-source license.
