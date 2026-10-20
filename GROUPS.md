# Groups and sender keys

Update the relay and Android app together for private group history (group API
protocol 2). One-to-one wire v3
remains unchanged. Group envelopes use the separate Carriex sender-key format v1.

## Using groups

On a server's chat list, open the pencil button and choose **New group**. The
creator is the permanent admin. Use the group's three-dot menu to invite a
device ID, choose a saved contact, or scan the person's **My ID** QR code.
Scanning opens an invitation confirmation for the current group and server.
Invited people see **Join group** and **Decline** in their chat list;
they receive no sender key before accepting. The admin can select another
person in **Group members** to remove them or revoke a pending invitation.
Members can leave. The admin closes the group with **Delete group**; admin
rights cannot be transferred. Saved history remains on each participating phone.
Selecting a person in **Group members** also offers **Rename member**. Names are
local to that phone and server, and update group message headers and activity.
The founding admin and signed device identities remain unchanged.

The Android conversation shows verified creation, invitation, join, removal,
leave, decline and closure updates as activity messages. The removed or leaving
person receives their terminal membership update; they do not receive later
group changes. An invitation does not grant access to group activity. The server
returns only events from the device's membership periods, starting with its own
join and ending with its leave, removal or closure. Rejoining never grants events
from an absence. Filtering precedes pagination and applies even to `after=0`.
Activity is stored encrypted on the phone and deduplicated by signed revision.
Existing cached groups discard ineligible activity and recover only permitted
events. Information already delivered by an older relay cannot be undisclosed.
Events appear at the point where the phone observed them relative to its saved
messages; they have no fabricated remote timestamp.

The composer clears and shows a pending message immediately, with a guard
against repeated button/IME submissions while saving. Local queueing precedes
network work, and each new queued message is pinned to its membership epoch.
A membership change fails uncertain messages rather than changing their
audience. Each send refreshes membership without downloading every group's
keys, incoming messages and delivery statuses. Joining and key preparation
show progress in the conversation.
Group invitations also alert while the app is open, using the existing message
request alert preference and Android notification permission. Tapping opens the
correct server's chat list. Repeated synchronization does not repeat an alert.

Groups support up to 32 members and pending invitations combined, with up to
64 groups per identity. Group titles currently remain as created.

## Membership authority

Every full membership snapshot is signed with its actor's device P-256 key.
Clients and relay check the public-key hash against the actor's 64-character
device ID. A snapshot includes the group ID, immutable admin, title, revision,
epoch, members, invitations, action, target, previous-state hash, and closed flag.
Existing members verify consecutive signed transitions, rejecting missing
updates, rollbacks, unauthorized changes and admin replacement. A new member
receives its own admin-signed invitation as initial identity information, never
the group's creation or earlier activity. `/join-proposal` supplies an unsigned
template for that device's own join, without the preceding event's action,
actor, target or old roster. Signing that proposal does not authorize sending keys.
`/decline-proposal` similarly lets an invitee decline after hidden intervening
changes, without downloading those events.

If the join immediately follows the signed invitation, that transition can be
verified directly. Otherwise the client waits for an admission checkpoint
signed by the permanent admin, binding the exact accepted join's group ID,
member, revision and state hash. The admin's app verifies its transition chain
and signs this automatically when online; no second manual approval is needed.
An unconfirmed client shows joining progress and distributes no sender key.
It resumes normal chain verification from its confirmed join, without receiving
intervening activity from before membership. The relay cannot manufacture a
checkpoint because it does not have the admin's signing key.

Admission signing bytes are ASCII, including the final newline:

```text
Carriex group admission v1
<group ID>
<joining member ID>
<join revision>
<join state SHA-256>
<permanent admin ID>
```

The signature is SHA256withECDSA using the admin's device key. The checkpoint
contains `version=1`, `group_id`, `member`, `revision`, `state_hash`, `admin`,
`auth_key`, and `signature`. `POST /groups/<id>/admissions` is admin-only and
accepts up to 100 checkpoints for exact accepted joins. The private events API
returns the matching proof only to that joining identity. Participation intervals
are transactionally maintained and reconstructed from existing signed events
when upgrading the database.

Only the founding admin may invite, remove, revoke or close. Joining requires
an invitation and the invited device's signature. Leaving or declining requires
the affected device's own signature. Concurrent changes use the previous hash
and revision as a compare-and-swap; synchronize before retrying a conflict.

The signing bytes are ASCII, including the final newline:

```text
Carriex group state v1
<group ID: 32 lowercase hex>
<revision: decimal>
<epoch: decimal>
<previous state SHA-256: 64 lowercase hex, all zero for creation>
<permanent admin ID>
<canonical base64 of UTF-8 group title>
<sorted member IDs, comma separated>
<sorted invited IDs, comma separated>
<actor ID>
<action: create/invite/join/remove/leave/decline/close>
<target ID, empty for create/close>
<closed: 0 or 1>
```

The state hash is SHA-256 of these bytes. Signatures use SHA256withECDSA with
canonical P-256 SPKI public keys. A revision advances on every change. An epoch
advances exactly when the member set changes. An invitation or its revocation
does not disclose keys or require rotation before the person has joined.

## Sender-key lifecycle

Each member independently generates a random 32-byte chain key, a fresh X25519 /
XEdDSA signing pair, and random 128-bit key ID for each epoch. Its distribution
contains the group ID, epoch, membership hash, sender ID, key ID, chain key and
public signing key. The private signing key is never distributed.

Distributions travel separately to every other current member inside the existing
authenticated X3DH / Double Ratchet encryption. They do not create one-to-one
chat messages or bypass contact requests. Pairwise ratchet updates and the exact
outgoing distribution batch are committed together in encrypted phone storage
before upload. Retrying an upload reuses the saved ciphertext.

On every accepted join, removal or voluntary departure, each remaining member
discards its old sending and signing secrets, creates new random keys and
redistributes them to the new roster. Offline members do this when they reconnect,
before sending. An online sender can send once its own distribution has been
published to all current peers; an offline member does not freeze everyone else.
The relay rejects stale epochs and sending before the sender's distribution is
complete. Removed members cannot retrieve group keys or new messages.

For each message, HMAC-SHA256(chain, 01) derives its encryption key and
HMAC-SHA256(chain, 02) derives the next chain. Encryption uses
XChaCha20-Poly1305 with a fresh 24-byte nonce. A sender signature authenticates
the associated data and ciphertext, preventing other recipients who know the
chain key from impersonating the sender. Associated data binds the group,
epoch, membership hash, sender, key ID, message counter and message ID.
The membership hash covers the group ID, epoch, immutable admin and sorted roster
under the distinct `Carriex group membership v1` domain.

The relay fans out one signed ciphertext to the current recipients. Phone
storage commits decryption, replay state and history before acknowledgement.
**Sent** means relay acceptance; **Received** means every original recipient's
delivery has been acknowledged. There are no read receipts. Receivers retain at
most 128 skipped message keys per sender and reject larger jumps, replayed
counters, invalid signatures and changed group context without advancing state.

Old receiving keys and original-recipient deliveries remain available through
the queue TTL so continuing members can read delayed messages across a join or
departure. New members receive no old distributions or history. Removed members'
queued deliveries and key packets are removed. A removed phone erases its local
group sender/receiver secrets when it synchronizes the signed change; a server
cannot erase an offline or modified phone. Previously decrypted history remains.

An uncertain outgoing ciphertext from an earlier epoch is marked **Failed**
instead of silently changing its audience. Copy and send it again if appropriate.

## Relay API and storage

All endpoints require the existing full device-authentication credential.
Count-only notification credentials cannot access groups.

- `GET /groups`: group IDs and accessible revisions, including final removal events.
- `POST /groups/state`: apply a signed creation or membership transition.
- `GET /groups/<id>/events?after=<revision>`: up to 100 signed transitions.
- `POST /groups/<id>/keys`: immutable complete per-recipient distribution batch for the current epoch.
- `GET /groups/<id>/keys?epoch=<epoch>`: packets addressed to the authenticated current member.
- `POST /groups/<id>/messages`: one opaque signed group ciphertext for the current epoch.
- `GET /groups/<id>/messages`: up to eight original-recipient queued ciphertexts.
- `POST /groups/<id>/ack`: acknowledge only the caller's deliveries.
- `GET /groups/<id>/statuses`: the caller's outgoing delivery states.

SQLite membership changes, permission checks and fan-out are transactional.
Group queues and invitations contribute to the existing private background count
and arrival revision. WebSocket `groups` events trigger synchronization; polling
recovers missed events. Acknowledged ciphertext is cleared while a digest keeps
submission retries idempotent. Membership records, key packets and queues have
explicit storage limits.

The relay can see titles, membership, invitations, routing, size and timing. It
does not receive sender secrets or message plaintext. It remains responsible for
availability and ordering: a malicious relay can withhold a signed update and
delay a client learning about a membership change. Signed chains prevent forged
changes and detectable rollback, but do not provide an external freshness oracle.
This implementation has not undergone an independent security audit.

Sender-key chain and distribution concepts were checked against the primary
[libsignal group cipher](https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/group_cipher.rs)
and [sender-key state](https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/sender_keys.rs)
implementations. The Carriex encoding and AEAD choice are specific to this app.
