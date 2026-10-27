# Security

**English** | [Русский](SECURITY.ru.md)

Carriex authenticates devices with P-256 challenge signatures and short-lived
bearer sessions. The server stores public keys, never device private keys.
Sending and inbox access are bound to the authenticated ID. See
[AUTHENTICATION.md](AUTHENTICATION.md) for the exact protocol and threat limits.

HTTPS/WSS is required for remote use. `CARRIEX_ALLOW_INSECURE_HTTP=1` is for local
development only. Trust proxy headers only behind an isolated trusted TLS proxy.
The paired launcher uses a persistent self-signed TLS key. Phones trust its public
key through an offline QR/text bundle, with live expiry and hostname checks. Obtain
the initial bundle through a trusted channel; substitution at pairing time can
substitute the server. Protect and back up the private identity directory. See
[PAIRING.md](PAIRING.md) for setup and renewal behavior.
Enrollment is open: ownership of a key does not establish a person's identity or
administrator approval. There is no revocation/admin flow. Ciphertext queues and
public X3DH bundles persist in SQLite; bearer sessions and socket registration
remain process-local. Keep one worker and deploy suitable ingress limits.

Optional Android notification checks use persistent, hashed, revocable credentials
restricted to the owner's pending count. These cannot send, download or acknowledge
messages. They reveal queue counts and arrival changes to their holder, and last
seven days by default. Android encrypts them with a Keystore key. See
[NOTIFICATIONS.md](NOTIFICATIONS.md) for scope, renewal, and scheduling limits.

Android now verifies X3DH signed prekeys and a P-256 signature binding each
encryption identity to the contact's full device ID. Compare that ID directly
with the intended person; a server-provided first-contact ID alone does not
identify a person. Changed pinned encryption identities are rejected. The relay
stores only public prekeys and opaque ciphertext, claims one-time keys atomically,
and rate-limits claims. Consumed public keys are deleted; monotonic publication
revisions prevent retry resurrection. Confirmed publication starts private-key
retention. Bounded session lifetimes, contact-specific session allowances, inbox
pagination, encrypted message requests and relay quotas limit storage abuse.
One-time-key fallback requires explicit opt-in. Update both phones and the relay
together. See [X3DH.md](X3DH.md) for the protocol and limits.
Android wire v3 adds classical Double Ratchet message-key evolution, DH turns,
bounded expiring skipped keys and transactional restart-safe state. Both phones
must upgrade together; fixed-key v2 sessions/envelopes are not reused. The current
prekey API remains compatible and the relay receives no ratchet secrets.
Protection of consumed keys and recovery after passive compromise depend on clean
DH contributions, randomness and deletion. Device control, identity compromise,
saved plaintext history, retained skipped keys and restored database snapshots
remain risks. There is no post-quantum or independent-security-audit claim.
Delivery receipts remain server-reported states. Optional recipient read reports
are off by default on Android and reveal viewing metadata to the relay and sender;
they are not cryptographic read proofs. Quarantined and hidden-delivery messages
cannot be reported read. Group messages retain delivery-only receipts.

Group membership changes are signed and hash-linked. The founding admin can
invite or remove people and sign shared group-name changes; invitees review invitations or opt into automatic
acceptance in Android settings, members can leave, and admin
rights cannot be transferred. Each membership epoch uses fresh per-sender chain
and signing keys, distributed through authenticated pairwise encryption. The relay
rejects stale-epoch sends and denies removed members access. Group titles and
membership are visible to the relay; it stores no sender secrets. Event history
is restricted on the server to each device's actual membership periods, including
after leave/rejoin. Invitations grant no activity history. New members bootstrap
from their own invitation and an exact join confirmed by the permanent admin's
signature when a direct invitation-to-join transition is unavailable. Clients
never distribute sender keys for an unconfirmed roster. Continuing
members retain old receiving keys only through the queue retention window for
delayed delivery. See [GROUPS.md](GROUPS.md) for exact behavior, quotas and limits.

Optional statistics retain hourly aggregate counts, sizes and timings. They add
no IDs, payloads or credentials to metric tables, but reveal aggregate activity
and add SQLite write overhead. Collection is disabled by default. The separate
viewer is read-only and loopback-only; the public relay exposes no statistics
endpoint. See [STATISTICS.md](STATISTICS.md).

Use the repository's GitHub Security tab to report vulnerabilities privately
if private reporting is enabled. Otherwise contact a maintainer privately
through their GitHub profile. Do not put sensitive payloads in public issues.
Include the affected version and reproduction steps.

Security fixes target the latest release; older versions have no support promise.
