# Device authentication (protocol v1)

The app generates an ECDSA P-256 key pair inside Android Keystore. It requests
StrongBox on Android 9+ and falls back to ordinary Android Keystore if StrongBox
is unavailable. The private key is non-exportable; its hardware isolation depends
on the device. Signing is allowed without a biometric prompt so reconnection can
run unattended. Authentication keys are separate from message-encryption keys.
App backup and device transfer are disabled to avoid restoring an identity without
its Keystore key. Reinstalling/clearing app data loses the identity; there is no
key recovery, export, or rotation flow yet.

The user ID is the lowercase, 64-character SHA-256 hex digest of the canonical
DER SubjectPublicKeyInfo public key. This replaces the old random `user-...` IDs.
Existing installations must share their new IDs. A different key cannot register
an existing ID, including after server restart. The server does not accept a
client-selected ID during enrollment. This is open device enrollment: proof of
key ownership is not administrator approval, person verification, or hardware
attestation.

## Exchange

All remote requests use HTTPS/WSS. The app's saved-server flow pins the public key
from an offline QR/text bundle; it verifies the live self-signed certificate,
validity dates, and hostname/IP without requiring a public CA. See
[PAIRING.md](PAIRING.md). Authentication redirects are not followed. The lower-level
transport permits HTTP only for literal loopback/localhost and the Android emulator
host address `10.0.2.2` for tests; the app's pairing UI requires HTTPS. The server
rejects HTTP by default (except public `/health`), including when an untrusted
request supplies `X-Forwarded-Proto: https`.

1. `POST /auth/challenge`, JSON `{"public_key":"<standard base64 DER/SPKI>"}`.
   Only canonical P-256 keys are accepted. Response contains `user_id`,
   `audience` (the configured public server URL), `challenge` (32 random bytes
   encoded as unpadded base64url), and `expires_in`
   (60 seconds). No identity is registered at this step.
2. The client first checks that `audience` equals its configured server base URL.
   Sign these exact UTF-8 bytes with `SHA256withECDSA`, with three newline
   separators and no trailing newline:

   ```text
   Carriex device authentication v1
   <audience>
   <user_id>
   <challenge>
   ```

3. `POST /auth/verify`, JSON `{"challenge":"...","signature":"<standard base64 DER ECDSA signature>"}`.
   Each challenge is consumed atomically once, including failed proofs. The server
   verifies the signature, records the public key, and returns `user_id`, `token`,
   and `expires_in` (3600 seconds). The token contains 32 cryptographically random
   bytes, encoded as unpadded base64url.
4. Supply `Authorization: Bearer <token>` on `/send`, `/messages/<user_id>`, and
   the WebSocket upgrade `/ws/<user_id>`. Tokens never appear in URLs. The server
   stores token hashes only. The app keeps tokens only in RAM.

The server audience is included in the signed proof to prevent a malicious
Carriex server relaying a challenge to impersonate the device at another server.
Production requires `CARRIEX_AUTH_ORIGIN` to be configured; it is never taken from
the HTTP Host header. The paired launcher sets it automatically to the advertised
URL. Local HTTP development may derive it from the local URL.

The server binds the session to one ID. HTTP `sender` must match that ID. Inbox
and WebSocket paths must match it too. WebSocket send frames may omit `sender`;
if present it must match. The server supplies the verified sender to routing.
Expired sessions cannot send/receive; idle WebSockets close with code 1008.
Clients renew through another challenge, including after an HTTP/upgrade 401,
WebSocket authentication expiry, or server restart. A stale socket failure cannot
invalidate a newer session established by another request.

## Storage and operational limits

`src/auth.py` owns the in-memory registry, outstanding challenges, and sessions.
It stores no device private key. Challenge/session entries expire; each map and
the device registry are capped at 10,000 entries. Authentication returns HTTP 429
when capacity is reached. Expired entries are pruned during authentication.
Deployment-level rate limits are still needed for an internet-facing service.
Registry capacity is intentionally bounded until persistence/admin controls exist.

Use a single server worker. Restart discards the registry, tokens, challenges,
and message queues; the same device can enroll again under the same key-derived
ID. A future shared database must preserve unique public-key/ID bindings and
atomic challenge consumption, and use shared session state before adding workers.
There is no device revocation/admin account management yet. The one-hour token
lifetime limits a stolen token's validity; private-key compromise requires a new
identity and notifying contacts.

TLS protects bearer tokens and the authenticated WebSocket stream. End-to-end
message encryption remains a separate protocol. Socket send acceptance is not a
delivery receipt, and this change does not implement durable delivery or an audit
of the existing peer key-exchange protocol.

## Running

For phones, use `start-server.bat` or `python -m src.pairing` and the QR/text setup
in [PAIRING.md](PAIRING.md). The launcher creates and preserves the server identity
and serves HTTPS/WSS directly. It disables the HTTP bypass and proxy-header trust.

For local development only:

```powershell
$env:CARRIEX_ALLOW_INSECURE_HTTP='1'
.\.venv\Scripts\python.exe -m flask --app src.app:app run --host 127.0.0.1 --port 5000
```

The HTTP endpoint above is for protocol test clients. To test the app on an
emulator, generate a paired server with `--address https://10.0.2.2:8443` instead.
For alternative API clients using public-CA TLS at a reverse proxy, set `CARRIEX_TRUST_PROXY=1`
only behind a trusted proxy that overwrites `X-Forwarded-Proto`. Keep the backend
bound to loopback or an isolated private network, preserve `Authorization`, and
proxy WebSocket upgrades. Do not expose that backend directly. The legacy
`compose.proxy.yaml` binds to loopback by default; its `.env` HOST setting still
takes precedence. Default `compose.yaml` now starts the paired HTTPS server.
Set `CARRIEX_AUTH_ORIGIN=https://chat.example.com` to the exact public base URL
used by clients, including a non-default port if applicable and without a trailing
slash. Use lowercase hostnames and omit the default HTTPS port 443. A different
address or origin produces a visible authentication error, not a signed proof.

## Verification

Server: `python -m pytest -q` runs real localhost authentication, impersonation,
replay (including concurrent replay), session/challenge expiry, restart, inbox
ownership, WebSocket binding, and existing messaging tests. Fixtures authenticate
with actual generated test keys; there is no authentication bypass.

From the Android project, run cross-language tests and Keystore checks with:

```powershell
$env:CARRIEX_TEST_PYTHON=(Resolve-Path ../Carriex-server/.venv/Scripts/python.exe).Path
$env:CARRIEX_TEST_SERVER_ROOT=(Resolve-Path ../Carriex-server).Path
./gradlew.bat :app:testDebugUnitTest :app:connectedDebugAndroidTest :app:assembleDebug
```

The JVM suite verifies signed challenge exchange, cache/concurrency behavior,
identity substitution, redirect rejection, reconnects, and actual Kotlin-to-Flask
messaging/session renewal/restart recovery. Cross-language tests are explicitly
skipped if the two environment variables are missing. The instrumentation test
loads the Keystore identity twice, checks that private key bytes are unavailable,
and verifies an actual signature. An emulator does not establish physical-device
StrongBox/TEE protection.

Implementation references: [Android Keystore](https://developer.android.com/privacy-and-security/keystore)
and [cryptography ECDSA](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ec/).
