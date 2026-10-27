# Archived local TLS deployment

**English** | [Русский](README.ru.md)

This private-CA/Caddy deployment was removed from the active setup because importing a certificate on every phone complicated onboarding. The active setup remains `docker compose up --build -d`, followed by entering the server's LAN IP and port 5000 in the app.

These files are preserved for future work, not loaded by the normal Compose deployment. HTTPS.md contains historical instructions. Its paths assume the deployment files are at the repository root: restore Caddyfile and compose.https.yaml there before using those commands, and port SERVER_ADDRESS from the archived .env.example into your configuration. The matching Android CA-import implementation is archived in the Android project's deprecated/local-tls directory.

No running containers, certificates, volumes or private .env settings were changed by this archival operation.
