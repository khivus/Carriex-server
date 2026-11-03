# Updating settings and fixing startup

**English** | [Русский](CONFIGURATION.ru.md)

Keep your existing `.env` when pulling updates. Missing optional settings use
defaults; copying a new example over the file is unnecessary. Keep the private
identity directory or Docker volume too, so phones retain the same trusted key.

## What changed in 0.7.0

The address settings are unchanged: `CARRIEX_HOST`, `CARRIEX_PORT` and
`CARRIEX_SERVER_NAME`. Section 08 adds optional limits for an internet-facing
relay. Commented lines do nothing; their descriptions show units and defaults.

| Setting (prefix each name with `CARRIEX_`) | Default | Purpose |
|---|---|---|
| `REGISTRATION_MODE` | `open` | `approved` requires local approval of each device ID; existing enrolled IDs are retained by the server migration. |
| `CONNECTION_LIMIT` / `CONNECTIONS_PER_IP` | 128 / 32 | Bound simultaneous connections, including those before authentication. IP limits are shared by users behind one NAT. |
| `REQUEST_TIMEOUT` | 15 seconds | Deadline for complete HTTP headers and, separately, the request body. |
| `WS_GLOBAL_LIMIT` / `WS_IP_LIMIT` / `WS_DEVICE_LIMIT` | 64 / 20 / 2 | Bound WebSocket connections. |
| `ENROLL_IP_HOURLY` / `ENROLL_GLOBAL_HOURLY` | 30 / 120 | Bound new-device registrations per hour. |
| `SENDER_PENDING_LIMIT` / `SENDER_STORAGE_BYTES` | 4,000 / 8,388,608 bytes | Bound queued storage occupied by one sender. This replaces the former 64-message limit for accepted contacts. |
| `MAX_DATABASE_BYTES` | 1,073,741,824 bytes (1 GiB) | SQLite size ceiling; excludes WAL, logs and backups. |

Do not uncomment every option. In particular, the example `REGISTRATION_MODE=approved`
opts into manual admission; leaving it commented retains normal open enrollment.
Message TTL and optional statistics already have their own sections. Section 09
groups legacy URL and proxy options separately from normal paired HTTPS settings.
See [limits, approval commands and recovery](HARDENING.md) for further controls.

## Why a pull can leave the server unable to start

The 0.7.0 production listener requires **gevent** on Windows as well as Linux.
`git pull` updates source files but does not install new Python packages into an
existing virtual environment. An older environment can therefore fail with
`ModuleNotFoundError: No module named 'gevent'`. This is a likely explanation
after a source-only update; the actual startup error is needed to confirm it.

One-time repair for an older Windows checkout, from the server folder:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\start-server.bat --check-config
.\start-server.bat
```

Linux/macOS uses `.venv/bin/python -m pip install -r requirements.txt`, then
`sh start-server.sh --check-config` and `sh start-server.sh`.

The updated native launchers automatically install the runtime lock when it
changes or a required package is missing. Internet/package-index access is needed
for that refresh. A failed install stops with a repair message; it does not proceed
to create identity files. Subsequent starts verify installed packages and skip pip.
An already-applied lock respects later manual package upgrades until the next lock
update. Direct `python -m src.pairing` does not install dependencies itself.

For Docker, pull the code and rebuild/recreate the service:

```sh
docker compose up -d --build
docker compose logs --tail 100 server
```

A container restart alone neither rebuilds the image nor reloads changed Compose
environment values. Keep the existing identity volume; do not delete it to repair
a package problem. If dependency refresh succeeds but startup still fails, inspect
the named configuration error, port conflict, or storage-permission error in the
log rather than replacing `.env` again.

## Automatic settings migration

Native startup and `--pair-only` compare the saved template fingerprint with the
current example. On a template update they restore section headings, blank lines,
descriptions and commented optional settings. Existing active values retain their
literal spelling, quotes and inline comments. Additional variables and personal
comments are retained under **PRESERVED ADVANCED SETTINGS AND PERSONAL NOTES**.
Legacy `CARRIEX_PUBLIC_URL` is preserved without enabling a conflicting example host.
Shell/CLI overrides are never copied into the file during automatic migration.

Before replacement, the server saves the original bytes as
`.env.backup-YYYYMMDD-HHMMSS-<suffix>` beside the file. It writes the new file through
an atomic replacement, retains UTF-8 BOM/line endings and file mode, and detects
edits made concurrently. Backups contain your settings, so keep them private.
An unchanged template causes no rewrite or extra backup on later starts. Runtime
limits and syntax are checked before automatic migration or identity creation.

Use these flags with either native launcher:

| Flag | Effect |
|---|---|
| `--check-config` | Validate and preview settings; no config/identity writes, listener or dependency downloads. |
| `--migrate-config` | Upgrade only the layout, with a backup. If missing, create a fully commented template without inventing an address. No identity or listener. |
| `--no-migrate-config` | Start using existing values without rewriting the settings file. |
| `--init-config` | Add missing address/port/name from the saved address or `--address`, using the categorized template. |

`--config path/to/custom.env` works with all these flags. If a valid file is
read-only or cannot be backed up, automatic migration warns and continues with the
validated values. Explicit `--migrate-config` instead reports failure. No migration
replaces the private server key, database or message history.

Docker Compose reads the host `.env` and passes selected values into the container;
the standard service does **not** mount that file. It cannot rewrite the host file
automatically. Keep your existing `.env`; new optional settings still use defaults.
To refresh its layout with the built image, run this explicit one-off command
from the checkout (the mounted directory must be writable by the container user):

```sh
docker compose run --rm --no-deps --entrypoint python --volume "${PWD}:/settings" server -m src.pairing --config /settings/.env --migrate-config
```

This creates only the host config/backup; it does not start a listener or modify
identity files. Recreate the service with `docker compose up -d` after editing
active values. Advanced Docker options must also be passed in Compose `environment`.
