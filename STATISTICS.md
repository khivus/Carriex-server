# Statistics for practical work

Collection is optional and disabled by default. Enable it in `.env`, then restart
using `start-server.bat`, `./start-server.sh` or Docker Compose:

```dotenv
CARRIEX_STATISTICS=1
CARRIEX_STATISTICS_RETENTION_DAYS=30
```

Native launchers also accept `--statistics` / `--no-statistics`, overriding `.env`.
`--check-config` shows the mode. Retention accepts 1–365 days.

From a second terminal in the server folder:

```powershell
# Dashboard at http://127.0.0.1:8766, updated every five seconds:
.\.venv\Scripts\python.exe -m src.statistics serve
# Terminal report:
.\.venv\Scripts\python.exe -m src.statistics show
# Hourly observations for a report/spreadsheet:
.\.venv\Scripts\python.exe -m src.statistics export --format csv --output experiment.csv
.\.venv\Scripts\python.exe -m src.statistics export --format json --output experiment.json
```

Linux/macOS uses `.venv/bin/python`. For a custom server directory/window:

```powershell
.\.venv\Scripts\python.exe -m src.statistics --data-dir D:\CarriexData --days 7 serve --port 8766
```

The viewer also reads `CARRIEX_IDENTITY_DIR` from `.env`. It opens the database
read-only and listens only on `127.0.0.1`, separately from the public relay. There
is no public statistics/admin endpoint or extra phone credential. The page offers
JSON/CSV downloads. For a remote server, use SSH forwarding or export on the server.

For Docker, set the same `.env` variables and recreate the server, then:

```sh
docker compose exec -T server python -m src.statistics --data-dir /var/lib/carriex show
docker compose exec -T server python -m src.statistics --data-dir /var/lib/carriex export --format csv > experiment.csv
```

## Persistence and interpretation

Hourly UTC aggregates persist in `statistics_hourly` and `statistics_meta` inside
the existing private `messages.sqlite3` (default `.carriex-server/messages.sqlite3`).
Old buckets are pruned during collection/startup. Disabling collection stops new
measurements while keeping retained history; it does not erase exports/file pages.

| Metric | Meaning |
|---|---|
| `messages.accepted` | New persisted messages, excluding exact retries |
| `messages.duplicate_submissions` | Submissions of an already accepted ID |
| `messages.size_bytes` | UTF-8 bytes of the opaque ciphertext field, including Android hex encoding |
| `messages.socket_handoffs` | New messages handed to a connected socket, not recipient delivery |
| `messages.acknowledged` | First recipient acknowledgements, excluding repeats |
| `messages.delivery_receipts` | Acknowledgements requesting sender-visible delivery reporting |
| `messages.ack_delay_ms` | Acceptance to acknowledgement, including offline wait/polling/client processing |
| `messages.quarantined` | Queue removal without a delivery receipt |
| `messages.expired` | Queued messages removed by TTL cleanup |
| `messages.rejected.*` | Size, capacity or route failures |
| `prekeys.published`, `prekeys.claimed` | Public OPKs uploaded/claimed; claims do not prove session establishment |
| `prekeys.publication_retries`, `prekeys.claims_without_opk`, `prekeys.rate_limited` | Directory retry/depletion/rate-limit activity |
| `http.METHOD.endpoint.Nxx_ms` | Server HTTP handling time by registered route and response class |
| `websocket.opened`, `websocket.closed` | Authenticated socket registrations/removals |

Each metric includes sample count, sum, minimum, maximum and mean. Counter totals
count events/items. Timing/size means describe observed values; their sums are not
elapsed experiment time. CSV has one row per metric/hour. Current queue length,
bytes and available OPKs are snapshots, rather than historical maxima. Blocking a
message is not recipient acknowledgement. Acknowledgement is not reading time.
HTTP timing excludes network transit/response transfer. Client encryption and
decryption durations and plaintext lengths are unavailable to the relay.

The collector adds no bodies, ciphertext, device/message IDs, IP addresses,
credentials or keys to statistics. The ordinary queue/directory still store data
required for relay operation. Aggregate measurements reveal activity; normal
server access logs are separate. Collection adds SQLite writes and affects timing.

## A repeatable experiment

1. Record app/server versions, devices, network, UTC start/end, collection mode and
   retention. Export a baseline and compare cumulative counters against it.
2. Send a known number of short messages while both devices are online. Compare
   accepted messages, handoffs, acknowledgements, sizes and handling times. Repeat
   with longer text below the app's 90 KiB UTF-8 limit.
3. Disconnect the recipient, send, inspect the queue, then reconnect. Observe the
   acknowledgement delay increasing with offline wait.
4. Restart the relay and confirm measurements persist. Exercise retries and prekey
   depletion on isolated test identities; claims do not equal completed X3DH runs.
5. Export CSV/JSON and report only actual observations. Compare runs with identical
   instrumentation. Mean/min/max are descriptive observations, not percentiles or
   a security audit. The collector does not create experimental results for you.
6. Enable count-only notifications on a recipient phone, put Carriex in the
   background, and send a known number of messages. Compare the configured
   interval, observed alert delay, pending counts, count GET request totals and
   acknowledgement delay after opening the app. Repeat with battery optimization
   enabled/exempted and different intervals. The HTTP metric is
   `http.GET.notifications.pending_count.2xx_ms`; it measures relay handling time,
   not Android scheduling or end-to-end notification latency.
