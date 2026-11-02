# Internet deployment and recovery

**English** | [Русский](HARDENING.ru.md)

Native Windows, Linux/macOS and Docker now use one bounded gevent production
listener. The paired address, TLS private key, certificate pin and authentication
audience stay the same. Stop the old server, install the updated dependencies,
and restart using the existing launcher. Preserve its identity directory/volume;
do not recreate keys to apply this update. SQLite schema changes are automatic.
Previously authenticated owners of messages, prekeys, inbox policies, notification
credentials and signed group participation remain enrolled during the upgrade;
an arbitrary recipient ID or unaccepted invitation does not enroll a device.

Update Android on receiving phones as well: acknowledgements now have a durable
retry outbox, accepted/automatically added contacts resynchronize their policy,
and transient queue/rate errors respect backoff instead of repeatedly flooding
the server. Existing history and encryption sessions are preserved.

## Why sending could stop

The previous relay allowed only 64 pending packets from an accepted contact and
two from an unknown sender. An offline friend could hit the first ceiling. A
failed acknowledgement or stale contact policy could leave the second ceiling
in place after a conversation was accepted. The accepted-contact ceiling is
removed. Unknown requests remain limited to two until the recipient accepts or
collects them; this protects the recipient from unsolicited floods.

Normal recipient capacity remains 1,000 pending messages / 16 MiB. Shared direct
storage remains 50,000 records / 128 MiB. Each sender may occupy 4,000 pending
messages / 8 MiB and at most 10,000 retained records. Collected ciphertext no
longer occupies the byte budget; lightweight delivery/idempotency records remain
until TTL. These bounds deliberately apply to a small relay. Increase deployment
capacity through measured configuration changes, rather than deleting queued
messages or disabling unknown-contact protection.

## Exposure defaults

Only forward the intended HTTPS TCP port. Do not publish the data directory,
statistics viewer, HTTP backend, Docker API, SSH/RDP or router management port.
Check both IPv4 and IPv6 firewall rules. The native production listener also
enforces limits before TLS/application authentication:

| Control | Default |
|---|---|
| Connections / connections from one IP | 128 / 32 |
| TLS handshake deadline | 5 seconds |
| Complete HTTP headers / complete request body | 15 seconds each |
| WebSocket write / write-lock deadline | 5 seconds |
| WebSockets globally / per IP / per device | 64 / 20 / 2 |
| Buffered complete WebSocket messages | 16 and 2 MiB per socket |
| WebSocket message / byte budget | 180 messages and 8 MiB per minute per socket |
| HTTP requests per IP / globally | 600 / 6,000 per minute, bounded token buckets |
| Authentication requests per IP / globally | 60 / 600 per minute |
| Challenges per device/source / sessions per device | 3 / 4; oldest sessions rotate out |
| New devices per source / globally | 30 / 120 per hour, persisted across restart |
| New pending group invitations per recipient | 16, separate from 64 accepted groups |

These limits include bursts. Source limits apply to a shared NAT address, so tune
them for the real user population. `.env.example` documents the main settings.
All `DEFAULTS` entries in `src/security.py` also accept a `CARRIEX_` prefix in
native configuration; advanced Docker overrides must explicitly pass additional
environment settings. Keep the WebSocket limit below total connection capacity.

`GET /health` exposes liveness/version/protocol compatibility required by Android.
Activity counts moved to authenticated `GET /diagnostics`. Sensitive responses
use `Cache-Control: no-store`. Public requests do not write per-request statistics.

## Private enrollment and local administration

Open enrollment remains available. Any stranger reaching an open relay can create
their own device key; authentication is not an invitation. For a friends-only
server set `CARRIEX_REGISTRATION_MODE=approved` and approve each public device ID
on the server computer. QR pairing still establishes server trust; it is not an
enrollment secret. There is no public administration endpoint or admin password.

```powershell
.\.venv\Scripts\python.exe -m src.admin --data-dir .carriex-server list
.\.venv\Scripts\python.exe -m src.admin --data-dir .carriex-server approve DEVICE_ID
.\.venv\Scripts\python.exe -m src.admin --data-dir .carriex-server revoke DEVICE_ID
.\.venv\Scripts\python.exe -m src.admin --data-dir .carriex-server block DEVICE_ID
.\.venv\Scripts\python.exe -m src.admin --data-dir .carriex-server unblock DEVICE_ID
.\.venv\Scripts\python.exe -m src.admin --data-dir .carriex-server cleanup
```

On Linux/macOS use `.venv/bin/python`. In Docker use
`docker compose exec server python -m src.admin --data-dir /var/lib/carriex ACTION DEVICE_ID`.
`list`/`cleanup` take no device ID. The operator must already have filesystem
access to the private server database. `revoke` invalidates existing full sessions
and count credentials; the device can authenticate again. `block` additionally
prevents new logins. Unblocking does not restore old tokens. A client can also
`DELETE /auth/session` to revoke its current session or `DELETE /auth/sessions`
to revoke all its sessions/count credentials. Connected sockets recheck access.

Inactive, unapproved, unblocked directory entries expire after 90 days, subject
to message retention, uncollected queues and current group access. Approved
devices and deny records are retained. Closed group history expires only after
the idle/queue retention window; active signed membership chains are preserved.
Historical declined/removed/closed groups no longer consume accepted-group slots.
Existing exhausted group allowances recover automatically through the new query;
do not delete history to restore membership capacity. Blocks apply to invitations
and prekey claims as well as direct messages. Unknown prekey claimants cannot
consume the final nine keys reserved for accepted/group contacts; standard
replenishment remains triggered below ten. Per-pair/source budgets limit churn.

## Proxy, storage and dependencies

Paired mode terminates TLS itself and ignores forwarded headers. In the advanced
proxy mode, keep the backend private and set `CARRIEX_PROXY_NETWORKS` to the exact
proxy source CIDRs (default: loopback only). The proxy must overwrite both
`X-Forwarded-Proto` and `X-Forwarded-For`, preserve Authorization and handle upgrades.
Headers from other sources cannot turn HTTP into HTTPS. A Docker host proxy may
appear as a bridge gateway; allow its verified address explicitly, not an entire
untrusted network. Keep `CARRIEX_ALLOW_INSECURE_HTTP=0` in deployed services.

Compose bounds memory (512 MiB), CPU, process count, open files, temporary space
and log retention. SQLite defaults to a 1 GiB database ceiling, with a WAL size
target; neither setting is a filesystem quota for WAL, backups or other files.
Use a volume/filesystem quota and free-space monitoring for a hard host-level
bound. The application does not truncate an existing database above the ceiling.

`requirements.lock` records the verified production package versions; Docker
installs it before the application. CI audits the lock against current public
advisories. To update it, upgrade in an isolated environment, run the server and
production TLS/WSS tests, run `python tools/lock_dependencies.py`, then
`python -m pip_audit -r requirements.lock --disable-pip --no-deps`. Vulnerability
databases and package versions change; an audit is a dated check, not a guarantee.

Application admission limits cannot protect a saturated internet uplink. Use
provider/router DDoS controls or restricted network access when that is required.
External port/TLS/firewall verification must be performed against the deployment
from another network; localhost tests do not establish its public configuration.
