# Local HTTPS setup

**English** | [Русский](HTTPS.ru.md)

The app defaults to HTTPS and port 443. The Python backend on port 5000 only speaks plain HTTP. This standalone deployment adds Caddy with a private CA for HTTPS and secure WebSockets, without exposing backend port 5000.

1. Give the server a stable LAN IP (for example, a DHCP reservation). Add `SERVER_ADDRESS=192.168.1.10` to `.env`, replacing the example with the actual LAN IP or hostname used by the phones. Do not include a URL scheme, path or port. Preserve other existing settings.
2. Allow incoming TCP port 443 from your LAN in the host firewall. No Internet port forwarding is necessary.
3. If the original HTTP stack is running, stop it with `docker compose down` (without `-v`). This restarts the relay and clears its in-memory queue. Start the TLS stack:

   ```sh
   docker compose -f compose.https.yaml up --build -d
   docker compose -f compose.https.yaml logs -f caddy
   ```

4. After Caddy has started, export ONLY the public CA certificate:

   ```sh
   docker compose -f compose.https.yaml cp caddy:/data/caddy/pki/authorities/local/root.crt ./carriex-local-ca.crt
   ```

   Display its certificate SHA-256 fingerprint on the server. With OpenSSL:

   ```sh
   openssl x509 -in carriex-local-ca.crt -noout -fingerprint -sha256
   ```

   Or with a JDK on Windows:

   ```powershell
   & 'C:/Program Files/Android/Android Studio/jbr/bin/keytool.exe' -printcert -file carriex-local-ca.crt
   ```

5. Transfer `carriex-local-ca.crt` to each phone through a trusted channel, such as USB. Never export or share the CA private key. In the updated app, enter the exact server IP/hostname and port `443`, keep **Use HTTPS** enabled, choose **Local server certificate**, and import the certificate. Compare the displayed SHA-256 fingerprint with the server's fingerprint before tapping **Trust CA**.
6. Tap **Connect** on both phones. The imported CA is trusted only for the configured address and port. Certificate-chain validation and hostname/IP verification remain enabled for HTTPS and WSS. Changing the address or port requires approving the CA for the new endpoint. Replacing the CA requires re-importing it.

Keep the `caddy_data` volume: it stores the CA private key and issued certificates. Protect the host and its backups; anyone with that CA key can impersonate this server. Do not use `docker compose down -v` unless deliberately replacing the CA. Use `-f compose.https.yaml` with subsequent Compose commands; this is a standalone file, not an override to merge with `compose.yaml`.

Verify the endpoint from a machine with curl:

```sh
curl --cacert carriex-local-ca.crt https://192.168.1.10/health
```

Expect `status: alive`. Do not use `-k` or disable verification. Access using a different IP or hostname must fail unless that name is included in the server certificate. Caddy renews local server certificates automatically. The backend keeps one Gunicorn worker because queues and connections are process-local.

## Security scope

This protects the client-to-server connection using an explicitly approved local CA. It does not fix the relay's unauthenticated user IDs, add authorization, or authenticate the chat key exchange. Those remain separate security work before treating Carriex as a production secure messenger. Do not expose this relay to untrusted networks merely because TLS is enabled.

The original `compose.yaml` remains the explicit HTTP development deployment. HTTPS never silently downgrades to HTTP. Previously saved app connection preferences are retained; switch existing installations to HTTPS and port 443 manually.

For a future public domain, replace `tls internal` with publicly trusted certificate provisioning and configure DNS/ACME reachability. Remove the private CA override for that endpoint in the app to use Android's system trust store.

References:
- https://caddyserver.com/docs/automatic-https
- https://caddyserver.com/docs/caddyfile/directives/reverse_proxy
- https://developer.android.com/privacy-and-security/security-ssl
