# X3DH and Double Ratchet: wire protocol v3

Carriex establishes sessions with X3DH and exchanges messages using the classical
Double Ratchet. Both phones must upgrade together. The existing v2 prekey relay
API remains compatible; the relay handles opaque v3 envelopes without ratchet
secrets. Saved local history remains readable; pending fixed-key outgoing
messages receive fresh IDs and are encrypted again.
Unsigned legacy key exchanges and legacy wire messages are rejected. There is no
automatic downgrade. An offline recipient must have connected once to publish keys.

## Cryptography and identity

X25519, XEd25519 signed prekeys, and HKDF-SHA256 follow
[X3DH](https://signal.org/docs/specifications/x3dh/). Public-key encoding is `05`
followed by 32 X25519 bytes. HKDF uses 32 `FF` bytes before DH1..DH3 (and DH4 when
a one-time key is available), a zero 32-byte salt, and `Carriex X3DH v2` as info.
The native XEdDSA adapter follows the [XEdDSA specification](https://signal.org/docs/specifications/xeddsa/)
using libsodium's scalar, point, SHA-512 and Ed25519 verification operations.
Verification rejects noncanonical Montgomery encodings and uses libsodium's
strict Ed25519 checks. No additional crypto dependency is downloaded.

The P-256 authentication identity signs these ASCII bytes, with no final newline:

```text
Carriex encryption identity v2
<64 lowercase hex device ID>
<canonical base64 X25519 identity public key>
```

Each client checks the canonical P-256 SPKI's SHA-256 against the contact ID,
verifies this binding, verifies the signed prekey, and pins the encryption
identity per server. Scanning a friend's device-ID QR through a trusted channel
authenticates this binding. Contact names are local labels and are not identities.
Changing a pinned encryption identity is rejected. A lost identity requires a
new device identity; there is no automatic same-ID key-reset mechanism.

The P-256 private key stays non-exportable in Android Keystore. X25519 identity,
prekeys and session secrets are encrypted in phone SQLite under a Keystore AES-GCM
key, and briefly enter app memory for use. Erasure is best effort: managed runtime,
SQLite pages/WAL, flash storage, and filesystem snapshots prevent a promise of
physical secure deletion. App backup/transfer stays disabled.

## Double Ratchet traffic

The state machine follows [Double Ratchet section 3](https://signal.org/docs/specifications/doubleratchet/).
This is a Carriex wire format and cryptographic instantiation, not Signal wire
interoperability. Header encryption and post-quantum ratchets are not implemented.

X3DH's 32-byte result initializes the ratchet root. Alice generates an independent
X25519 ratchet pair and initializes against Bob's advertised signed prekey.
Bob initially uses that signed-prekey pair, derives the receiving chain on the
first authenticated receive, then generates a fresh pair and sending chain before
replying. Subsequent new peer ratchet public keys trigger receive/send root updates
and fresh local key generation. The original X3DH shared secret and ephemeral
private key are not persisted. Stored state contains the current root and DH pair,
current send/receive chains, counters, and bounded skipped-message keys.

`KDF_RK` uses HKDF-SHA256 with the old root as salt, raw X25519 DH output as input,
`Carriex Double Ratchet v1 root` as info, and 64 bytes of output (root then chain).
`KDF_CK` uses HMAC-SHA256(chain, `02`) for the next chain and HMAC-SHA256(chain,
`01`) for the one-use message key. Old chain/root/DH values are replaced; message
keys are erased after use to the extent supported by the managed runtime/storage.
Messages use XChaCha20-Poly1305 with a fresh random 24-byte nonce prefixed to the
ciphertext. Header DH keys use canonical raw 32-byte X25519 encoding in base64.

The initial authenticated setup bytes are: ASCII `Carriex session v3\n`, the two
`05 || X25519 identity` encodings, then these ASCII fields in order, each preceded
by a four-byte big-endian byte length:

```text
sender, recipient, identity_key, auth_key, binding, recipient_identity,
ephemeral, signed_id, one_time_id, created_at, protocol, ratchet_key
```

`created_at` is Unix milliseconds as decimal text; `protocol` is exactly
`Carriex Double Ratchet v1`; `ratchet_key` is Alice's initial ratchet public key.
The session ID is SHA-256 of these setup bytes. `one_time_id` is empty for explicit
fallback. First arrivals must advertise that initial ratchet key, even when the
first received message has a nonzero sequence number.

DATA envelopes contain `version:3`, `sid`, `mode` (`init` for the X3DH initiator,
`reply` for the responder), `ratchet:{dh,pn,n}`, and base64 `ciphertext`. Initiator
envelopes always repeat the original setup `header`, including after DH turns,
so reordered opening messages remain decryptable. The mode describes the session
role, not the current ratchet turn. `pn` is the previous sending-chain length;
`n` is the current zero-based message number. They must be JSON integers, not
strings/floats, in the nonnegative signed-32-bit range (`n` at most 2^31-2).

Associated data is ASCII `Carriex message v3\n<sid>\n<mode>\n<sender>\n<recipient>\n<message ID>\n`,
followed by the canonical setup bytes, then `05 || dh || uint32_be(pn) || uint32_be(n)`.
Thus identities, routing, message ID, setup, public ratchet key and counters are
all authenticated. The body includes the original sender timestamp.

Skipped keys are indexed by remote DH key and sequence number. At most 1,000 keys
may be skipped/stored in a session and 2,048 stored per contact across sessions.
A gap beyond 1,000 is rejected before unbounded computation. Skipped keys expire
after the largest advertised queue TTL from derivation, are pruned during message
processing/maintenance, and are removed only after successful authentication.
Late messages beyond those limits cannot be decrypted. Replays are rejected;
ordinary transport redelivery is acknowledged from durable message-ID history.
Failed authentication never commits ratchet counters, DH turns or key deletions.

Ratchet state and exact outgoing ciphertext commit together before network send.
Retries resend saved bytes within the recipient retention window, including after
the 30-day new-encryption cutoff, without advancing the ratchet. Plaintext is
limited to 90 KiB UTF-8 and final transport size is checked before committing any
sending state. Permanent rejection is marked Failed instead of retried forever.
For an unrecoverable gap, **ID & verify > Restart secure session** retires sending
eligibility and makes the next message start a fresh X3DH exchange; retained keys,
history and existing ciphertext are preserved. Incoming state, prekey
consumption and plaintext history commit together before acknowledgement. State
and skipped keys survive process restart in Android Keystore-encrypted SQLite.

There is a 4,096-session limit per scope, 16 retained sessions per contact, and four
new sessions per contact per day, counted using the receiver's admission clock.
Unknown senders enter message requests without
creating sessions; up to 128 contacts are supported. Simultaneous initiation
retains both sessions and selects the newest usable session, breaking ties by ID.
Sessions send for 30 days before a fresh X3DH bootstrap; current ratchet state is
retained until session creation plus 37 days and the largest advertised queue TTL.
Saved history remains readable. Expired pending wire data is marked Expired; copy
its text and send again. Cleanup runs during app activity, not while the app is off.

**Limits:** key evolution is designed to protect consumed message keys after their
removal and to recover from passive state compromise after fresh, uncompromised
DH contributions. Current chain keys expose future messages in that chain until
fresh DH input; retained skipped keys expose their specific messages. Device
control, identity theft, active attacks, poor randomness and recoverable old state
can defeat these protections. There is no anti-rollback guarantee for restored
SQLite snapshots or forensic secure-deletion guarantee. Saved plaintext history
is still accessible to a compromised unlocked app. The protocol remains classical,
not post-quantum, and has not had an independent security audit. The relay sees
routing, timing, lengths and public ratchet headers; it can withhold keys/messages
and lie about delivery receipts.

## Relay endpoints

All endpoints require the existing bearer authentication and HTTPS outside local
development. Responses use `Cache-Control: no-store`.

| Endpoint | Purpose |
|---|---|
| `POST /prekeys` | Publish own bundle and at most 100 one-time prekeys |
| `GET /prekeys/status` | Own available count, revision, last receipt and `message_ttl_seconds` |
| `POST /prekeys/<peer ID>/claim` | Atomically return a bundle and consume at most one key |

A publication contains `version:2`, monotonic integer `revision`, random
32-hex `publication_id`, `identity_key`, `auth_key`, `binding`,
`signed_prekey:{id,key,signature}`, and `one_time_prekeys:[{id,key}]`.
A claim returns `user_id` and the certificate/signed-prekey fields plus
`one_time_prekey:{id,key}` or `null`. Keys/signatures are canonical base64;
prekey IDs are 32 lowercase hex characters. The first eight hex characters of
each newly published one-time-key ID encode its publication revision.
Clients verify XEdDSA; the relay
validates the certificate binding and public-field sizes. It stores no private keys.

SQLite claims are atomic, including concurrent requests. Consumed and expired
public keys are physically deleted from the directory. The relay retains only
the latest publication's SHA-256 manifest digest and receipt per owner, without
keeping another copy of consumed public keys. An identical same-revision
retry returns that receipt without inserting keys. Changed same-revision or
stale uploads are rejected; the next revision must advance by one. A new directory
entry accepts the phone's existing positive counter. Revision-prefixed
key IDs prevent an old consumed key ID from returning in a later publication.
Keep the relay database durable: losing its revision state also loses its replay
history; restoring an old database snapshot is not protected against rollback.
Missing peers return 404, invalid
bundles 400, identity/key-ID conflicts 409 and capacity/rate limits 429. Capacity
is 200 available keys per owner, 20,000 globally and 4,096 owners (the last two
are configurable with `PREKEY_GLOBAL_LIMIT` and `PREKEY_OWNER_LIMIT`).
Claims are limited to 30 per authenticated sender
and 100 per recipient per minute; those counters survive restart. Limits mitigate
accidental/excessive requests but do not prevent Sybil denial of service.

Phones initially generate 50 one-time keys and replenish below 10, subject to a
2,048-private-OPK inventory cap, 50 new keys per six hours and 200 per day. Budgets
persist across reconnects/restarts. A depleted budget pauses generation and shows
a warning; established sessions keep working. Existing private keys are retained
until their safe deadline rather than deleted to make room. Prekey inventory
maintenance runs on publication, not on each message. Maintenance
runs on connect and hourly while polling. The exact pending publication is stored
before upload. Only a matching successful receipt activates the new signed key,
retires the previous one and starts private-key retention deadlines. Lost responses
are recovered through the status receipt. Signed prekeys rotate after seven days
of confirmed activation; retired private keys remain for the advertised TTL plus
37 days. One-time public keys expire seven days after upload. Unconsumed private
keys remain for the TTL plus 44 days after confirmed publication, covering the
claim window, 30-day session sending window and delayed queue delivery. Consumed
private keys are removed in the transaction accepting their first message.
Unconfirmed publication keys are protected from premature cleanup. Clients support
queue TTLs up to 365 days, remember the largest seen TTL, and extend existing
retention deadlines when it increases. These are logical row limits/deletions,
not guaranteed physical SQLite-file compaction or forensic erasure.

Sessions without a one-time key are disabled by default for both initiation and
acceptance. A user may explicitly enable fallback in **Chat security**; **Contact
ID** displays the protection recorded for the latest established/received session.
Exhausted keys otherwise produce an actionable error and require replenishment.

## Inbox isolation and storage bounds

`GET /messages/<owner>?after=<cursor>` pages queued entries by an opaque integer
cursor, 500 per page. The client parses entries separately and continues through
later pages. Invalid ciphertext is quarantined in encrypted local storage and
retired from the relay with `POST /messages/<owner>/ack`, `quarantine:true`.
This sends no delivery receipt. Explicit acceptance after successful decryption
can send a normal acknowledgement later.

Unknown senders appear under **Message requests**. Accepting adds the contact and
attempts decryption; invalid requests can be discarded or blocked. Quarantine is
bounded to 64 entries, two per sender and approximately 4 MiB per server scope,
with a 30-day local retention window. Additional requests are discarded with an
error when full. The client publishes up to 128 contacts and 128 blocked IDs using
`POST /messages/<owner>/policy`; these lists are visible to the relay. Blocking
retires queued ciphertext without a receipt and rejects subsequent sends.

The relay limits unknown senders to two queued entries each and 32 collectively,
known contacts to 64 each, and recipients to 1,000 total. Ciphertext limits are
256 KiB per message, 16 MiB per recipient and 128 MiB globally; all message rows,
including receipt records, are capped at 50,000. Inbox policies have a 4,096-owner
cap. TTL cleanup removes expired receipt/quarantine bookkeeping. These bounds
limit growth but do not guarantee availability against many enrolled attackers.

## Crash safety and migration

The phone commits session state and the exact encrypted outgoing payload together
before sending. Incoming authentication, session persistence, one-time-key removal,
and history insertion commit together before UI notification or acknowledgement.
Failed authentication rolls everything back. Message IDs are unique within each
server scope. Database upgrades preserve bodies and timestamps, remove obsolete
pending exchanges, and re-encrypt only outgoing messages still marked Sending.
Old fixed session keys are no longer loaded by messaging. The relay must support
publication receipts/revisions and inbox policy endpoints from the v2 prekey API.
Database version 7 removes fixed-key session roots while preserving identity keys,
prekeys, pins and history. Fixed-key v2 envelopes are rejected without downgrade.
Both phones must upgrade; the current v2 prekey API needs no ratchet-specific
server change. A fresh app installation cannot recover old private keys.
Sending legacy messages with an already-saved wire payload receive a fresh message
ID and are resealed locally during migration, avoiding conflicts if the relay
already accepted the old ciphertext but its HTTP response was lost. If the old
message was already received before upgrading, this uncertain-delivery cutover can
produce a duplicate. Finish pending delivery on both old clients before upgrading
when possible. Queued legacy ciphertext itself is not converted by the relay.

## Verification

Server API tests use actual localhost HTTP and test owner binding, malformed
uploads, concurrent claims, rate limits, conflicts and restart persistence.
Android `X3dhAndroidTest` runs real JNI and encrypted SQLite, checks independent
Python XEdDSA and three/four-DH vectors, tampering, rollback, restart, simultaneous
initiation, and reordered delivery. Recreate public X3DH and ratchet vectors with `Carriex/tools/x3dh_reference_vectors.py`
and `Carriex/tools/double_ratchet_reference_vectors.py` using the server's Python environment.
`DoubleRatchetTest` checks independent Python KDF/DH vectors, reorder across chains,
replay/tamper rollback, counter limits, key expiry and compromise boundaries.
`DoubleRatchetAndroidTest` checks the vectors with real JNI and restart-safe
encrypted SQLite/outbox/skipped keys; storage tests cover the v6-to-v7 migration.

For the full Android-to-Flask test, start an isolated local relay on port 18765
with `CARRIEX_ALLOW_INSECURE_HTTP=1` and a temporary `CARRIEX_DATA_DIR`. Run on an
Android emulator from `Carriex`:

```powershell
.\gradlew.bat :app:connectedDebugAndroidTest '-Pandroid.testInstrumentationRunnerArguments.class=com.example.carriex.crypto.x3dh.X3dhServerAndroidTest' '-Pandroid.testInstrumentationRunnerArguments.x3dhServer=http://10.0.2.2:18765'
```

The live test verifies offline first-message delivery, opaque queued ciphertext,
reply encryption, recipient restart and further DH ratchet turns without another
prekey claim. Without the server argument it explicitly skips this one live test.
