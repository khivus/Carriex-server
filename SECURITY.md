# Security

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
administrator approval. There is no revocation/admin flow or durable storage yet.
Deploy suitable rate limits and keep one worker until shared storage exists.
Payload encryption and peer verification remain the client's responsibility.

Use the repository's GitHub Security tab to report vulnerabilities privately
if private reporting is enabled. Otherwise contact a maintainer privately
through their GitHub profile. Do not put sensitive payloads in public issues.
Include the affected version and reproduction steps.

Security fixes target the latest release; older versions have no support promise.
