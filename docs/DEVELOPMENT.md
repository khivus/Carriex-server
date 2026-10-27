# Carriex Server

**English** | [Русский](DEVELOPMENT.ru.md)

A Flask and Flask-Sock server that relays opaque encrypted message payloads
over HTTP and WebSockets. It does not encrypt or decrypt payloads itself.

## Pairing phones (recommended)

Run `start-server.bat` on Windows, supply your reachable HTTPS IP address, and open
the generated `.carriex-server/pairing.html`. Phones scan its QR or import its text,
save the server, and connect with its pinned key. No registered domain, public CA,
or additional phone app is required. See [PAIRING.md](PAIRING.md) for installation,
home-router reachability, key backups, and the direct-TLS Docker option.

## Local API development

Requires Python 3.11 or newer.

Device authentication is required. See [AUTHENTICATION.md](AUTHENTICATION.md)
for the protocol, TLS setup, and migration from old unauthenticated IDs.
The [X3DH directory and encrypted-envelope protocol](X3DH.md) documents the
authenticated `/prekeys` APIs, client key binding, rotation and retry rules.

```sh
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell instead:
# .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
# Local development only; PowerShell: $env:CARRIEX_ALLOW_INSECURE_HTTP='1'
export CARRIEX_ALLOW_INSECURE_HTTP=1
python -m flask --app src.app:app run --host 127.0.0.1 --port 5000
```

`python main.py` now launches the paired HTTPS server, with debugging disabled.
The explicit HTTP command above remains available for local protocol tests.

## Archived TLS setup

The old private-CA deployment is archived in [deprecated/local-tls](../deprecated/local-tls/README.md).
The active app now trusts individual self-signed server keys through QR/text
pairing, while still checking HTTPS/WSS certificates and hostnames.

## Docker behind a reverse proxy (alternative API deployment)

For the paired Android app, use `compose.paired.yaml` as described in
[PAIRING.md](PAIRING.md). The legacy configuration below is for clients using
public-CA TLS at a reverse proxy; that certificate cannot be imported as a paired
self-signed server certificate in the app.

```sh
docker compose -f compose.proxy.yaml up --build -d
docker compose -f compose.proxy.yaml logs -f server
docker compose -f compose.proxy.yaml down
```

Compose publishes port 5000 on loopback by default. Existing `.env` HOST/PORT
values override this. Keep the backend private and terminate HTTPS at a trusted
proxy; set `CARRIEX_TRUST_PROXY=1` only when that proxy overwrites forwarded scheme
headers. Set `CARRIEX_AUTH_ORIGIN` to the exact public HTTPS base URL used by
clients. For local development, explicitly set `CARRIEX_ALLOW_INSECURE_HTTP=1`.
Neither option disables authentication. The image runs as a non-root user and
checks the public `/health` endpoint.

Without Compose:

```sh
docker build -t carriex-server .
docker run --rm -p 127.0.0.1:5000:5000 carriex-server
```

The container uses one Gunicorn worker with 100 threads. Active WebSocket
connections occupy threads, so leave capacity for HTTP requests. Do not increase
workers or scale replicas: live connections and authentication sessions are
process-local. Queued ciphertext, public prekeys, and restricted notification
credentials persist in SQLite. Preserve the private data directory on restart.

## API

| Endpoint | Behavior |
| --- | --- |
| `GET /health` | Status, project version, connected users and clients |
| `POST /auth/challenge` | Starts proof of possession for a P-256 public key |
| `POST /auth/verify` | Verifies a one-time signature; enrolls device and issues session |
| `POST /send` | Accepts `id` (32 lowercase hex), `sender`, `recipient`, `ciphertext`; durably queues and offers live delivery |
| `GET /messages/<user_id>?after=<cursor>` | Lists up to 500 pending messages with pagination cursors |
| `GET /messages/<user_id>/count` | Returns only `pending_count` and arrival `revision`; does not download/ack messages |
| `POST /notifications/token` | Issues/replaces a persistent credential restricted to the owner's count GET |
| `DELETE /notifications/token` | Revokes that count credential; requires full device authentication |
| `POST /messages/<user_id>/ack` | Accepts `ids`, optional `report_delivery` or `quarantine`; quarantining suppresses receipts |
| `POST /messages/<user_id>/policy` | Sets bounded contact/block lists and reserves inbox capacity |
| `GET /statuses/<user_id>` | Returns sender-visible `queued`/`received` states |
| `WS /ws/<user_id>` | Offers pending and live messages; supports `ack` and receipt events |

The messaging endpoints and WebSocket upgrade require `Authorization: Bearer <token>`.
Use the proof exchange in [AUTHENTICATION.md](AUTHENTICATION.md) to obtain it.
The [notification protocol](NOTIFICATIONS.md) describes count-only credentials,
Android scheduling, custom intervals, and practical measurement.
IDs below are placeholders for full 64-character public-key fingerprints.

WebSocket clients send `{"type":"health"}` or
`{"type":"send","recipient":"bob","ciphertext":"encrypted-payload"}`.
The connection's user ID supplies the sender. Replies use `health`, `sent`, or
`error`; deliveries have the shape
`{"type":"message","message":{"id":"...","from":"alice","ciphertext":"encrypted-payload","timestamp":"..."}}`.

User IDs are authenticated and inbox access is restricted to their owner.
Message retrieval is non-destructive. The server keeps ciphertext until an
acknowledgement or TTL expiry, and retries are idempotent by message ID.
Public-key/session storage is currently in memory. Use TLS and deployment-level
rate limits for remote use.
See [SECURITY.md](SECURITY.md).

## Checks and packaging

```sh
python -m pytest -q
python -m ruff check .
python -m build
```

See [tests/README.md](../tests/README.md) for integration test details. Dependencies
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

### WebSocket recovery checks

WebSocket heartbeat pings run every 25 seconds. Reconnecting clients receive
queued messages; a failed backlog send restores the failed item and unsent tail.
Run `.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider` on Windows.
Tests start isolated localhost servers and include reconnect/backlog delivery and
overlapping connections for the same user. Queues persist across server restart;
socket send success does not prove recipient receipt.
