# Android count notifications

**English** | [Русский](NOTIFICATIONS.ru.md)

In Carriex, open the top-left menu and choose **Settings > Notifications**. Enable checks,
allow Android notifications, and select the saved servers to check. The default
interval is **15 minutes**. Custom seconds, minutes, hours, and decimal values
are accepted, with a minimum of one second. **Apply interval** saves the choice.

At 15 minutes or longer, Android JobScheduler handles persistent, network-aware
periodic work. Android can defer checks during idle periods. Shorter intervals
use a user-enabled foreground service with an ongoing status notification. They
use more battery and remain best effort. There is no permanent wake lock or
exact alarm. Android may require extra vendor-specific background settings.
Force-stopping Carriex stops checks until it is opened again. Normal reboot and
app-update recovery reschedule enabled checks; if Android refuses a background
service start, reopening Carriex resumes scheduling.

The optional battery optimization prompt explains the tradeoff and lets the user
keep the current setting. **Battery optimization** opens this choice again.
Exemption improves access during idle periods; it does not guarantee precise
notification timing. Android notification permission and channel settings remain
under the user's control. Google Play distribution requires review of the
declared `specialUse` foreground service for intervals below 15 minutes.

## Requests and invitations

Separate **message request alerts** and **group invitation alerts** default to on.
While connected in the foreground, verified invitations and locally saved unknown
contact requests can notify immediately. Both notification types open the selected
server's **Requests** page, with message requests and group invitations together.
Repeated synchronization does not re-alert a dismissed invitation; accepting,
declining, revocation, or leaving clears its alert. Background count checks include
pending invitations but do not download group details. Specific invitation review
becomes available after opening Carriex and connecting.

**Settings > Chats** offers optional automatic acceptance of new contacts and group
invitations. Both options default to off, retain block rules, and apply to saved
servers. **Settings > Privacy** contains chat-security options and optional read
reporting. Read reporting defaults to off and only applies to visible direct-chat
messages. Delivery acknowledgements remain separate from viewing.

## What runs in the background

Leaving the app closes its live messaging connection and five-second inbox
refresh. Background checks read only counts, through the saved server's pinned
HTTPS connection. They do not retrieve ciphertext, decrypt, download history,
publish prekeys, acknowledge messages, or generate delivery receipts. Returning
to the app reconnects the previous active server and preserves the current page
and drafts. Opening a pending-message notification connects its saved server.

Notifications display the server name and total number of queued, unexpired
messages. This includes message requests, group messages, and group invitations; it is not a local unread-chat count.
The notification contains no sender identity or message preview. One notification
per server is updated in place. Dismissing it suppresses repeats for the same
arrival revision. A new arrival can notify even if the total count is unchanged.
Zero pending messages clears the alert.

Foreground use skips automatic background checks. The **Check now** button can
fetch counts explicitly without posting a system alert over the visible app.
Checks share one worker, reuse TLS connections, and skip unavailable networks.
Failures back off per server, with persisted last results and errors shown in
settings. Requests have bounded response sizes and timeouts. A pass has a
50-second budget; a large number of slow/unavailable servers may need multiple
scheduled passes.

## HTTP protocol

1. With the existing device-authentication bearer session, send
   `POST /notifications/token` with `{}`. Response:

   ```json
   {"token":"<43-character base64url secret>","expires_in":604800,"user_id":"<device ID>","scope":"notifications.count"}
   ```

2. Reuse this credential in `Authorization: Bearer <secret>` for
   `GET /messages/<own-user-id>/count`. Response:

   ```json
   {"pending_count":2,"revision":108}
   ```

3. Renew after expiry or HTTP 401 using normal device authentication. A full
   device session can also read its own count. `DELETE /notifications/token`
   with full authentication revokes the count credential.

The count credential cannot download messages, send, acknowledge, access other
devices' counts, read prekeys, or issue/revoke credentials. It lasts seven days
by default, survives relay restarts, and is replaced on reissuance. The relay
stores only its SHA-256 hash in SQLite, with one credential per owner and a
4,096-owner limit. Full bearer sessions remain memory-only. On Android the count
credential is encrypted with an Android Keystore AES-GCM key and scoped to the
paired server identity and local device. Tokens never appear in URLs.

Count GETs use a covering SQLite index without reading ciphertext or modifying
queue rows. `revision` is the greatest arrival sequence among pending messages,
or zero for an empty queue. It can decrease after expiry/acknowledgement; clients
retain a high-water mark. The underlying sequence survives empty queues and
restarts. Duplicate submissions do not increment it. Legacy queued messages use
revision zero until new arrivals; a client's first nonempty check still alerts.
Responses have `Cache-Control: no-store`. Counts and timing remain metadata
visible to the relay and to a holder of this restricted credential.

Update the relay before enabling notifications on phones. An older relay returns
HTTP 404; Carriex shows an upgrade message and backs off rather than fetching a
full inbox as a fallback. Ordinary chat remains compatible.

With [statistics](STATISTICS.md) enabled, count request totals and latency appear
as `http.GET.notifications.pending_count.2xx_ms`. Use these with message and
acknowledgement metrics to compare polling intervals in practical work. Stored
statistics contain aggregate endpoint measurements, not device IDs or tokens.

Android references: [periodic jobs](https://developer.android.com/reference/android/app/job/JobInfo.Builder#setPeriodic(long)),
[idle restrictions](https://developer.android.com/training/monitoring-device-state/doze-standby),
[foreground service types](https://developer.android.com/develop/background-work/services/fgs/service-types#special-use).

## Optional direct-message read reports

With a full device bearer session, a recipient may send
`POST /messages/<own-user-id>/read` with `{"ids":["<32-character lowercase hex ID>"]}`.
At most 500 IDs are allowed. Only the authenticated recipient's messages that have
already been delivered with visible delivery receipts are eligible. Queued,
quarantined, hidden-delivery, expired, and other recipients' IDs are ignored.
The response is `{"read":1}` for one newly updated message; retries return zero.
The sender receives `{"type":"receipt","id":"...","state":"read"}` over its
socket and sees `read` from `GET /statuses/<own-user-id>`. Read state survives relay
restart for the existing message retention period. Count-only credentials cannot
report read status. This is optional relay-reported viewing metadata, not proof of
human reading. Updated clients are needed to display the additional state.
