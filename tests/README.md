# Integration tests

**English** | [Русский](README.ru.md)

Run from the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Pytest starts a fresh Flask server process on `127.0.0.1` with an available
port for each test, waits for `/health`, and stops the process afterward.
You do not need to start a server manually. HTTP and WebSocket clients connect
to the same server over real sockets. Tests inspect status codes and JSON
responses without importing the app or accessing its in-memory state.

A fresh process keeps message queues and connections isolated between tests.
Startup failures include the server log; requests and startup have timeouts.
Dependencies are listed in the root `requirements.txt`.

All messaging fixtures generate test keys and complete the real challenge/signature
exchange. `raw_client` is used for rejection/attack tests; there is no authentication
bypass. Authentication coverage includes forged signatures and sender IDs, replay,
concurrent replay, server-origin binding, session expiry, unauthorized WebSocket
upgrades, inbox ownership, and recovery after server restart.

`test_pairing.py` invokes the shipped pairing CLI in a subprocess, uses temporary
identity directories, checks persistent keys and renewal, validates generated
artifacts, and connects through a real HTTPS/WSS listener. It verifies that the
default system trust rejects the self-signed server. The Android cross-language
test additionally decodes the generated PNG QR and uses the actual Kotlin paired
client for authentication and message delivery.

`test_config.py` verifies shared `.env` settings, CLI/environment precedence,
invalid settings, QR refresh with key preservation, and real configured TLS
listeners. The port-443 test skips only if that port is occupied or the OS denies
binding it. Config tests use isolated temporary files, not the operator's `.env`.

With Docker running, use `python tests/check_docker_pairing.py` for an additional
default-Compose check. It builds a uniquely named test project, publishes only on
loopback, verifies HTTPS and authenticated WSS, edits its temporary `.env`, and
checks that reconfiguration preserves the key. It removes only its own test
containers/volume afterward. Normal `pytest` does not require Docker.

`test_config_migration.py` and `test_config_migration_cli.py` cover categorized
upgrades, exact backups, literal/custom/legacy values, personal comments, BOM/line
endings, future templates, repeat launches, read-only files and concurrent edits.
CLI checks also verify that checks/failed limits/missing gevent do not rewrite
settings or create identity files. `test_bootstrap.py` simulates dependency refresh
and download failures without changing installed packages. The Docker check also
exercises the documented explicit host-file migration with a writable test mount.
