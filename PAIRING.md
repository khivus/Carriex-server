# Pair a phone with your own server

For the simplest step-by-step setup, start with [README.md](README.md).
This page contains networking, identity, and advanced configuration details.

Carriex can use an IP address and its own TLS certificate. You do not need to
register a domain, buy a certificate, install a certificate system-wide, or install
another phone app. The server creates a persistent signing key and a self-signed
certificate. Its QR/text bundle contains the **public certificate**, address, and
display name. The phone saves that server key and checks it on every connection.
HTTPS and WSS provide the encrypted connection; the device's separate Android
Keystore key authenticates its user ID.

## Windows home machine

From the server folder, install dependencies once (Python 3.11+):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Set `CARRIEX_HOST`, `CARRIEX_PORT`, and `CARRIEX_SERVER_NAME` in the root `.env`,
then run `start-server.bat`. Use your machine's actual Wi-Fi/Ethernet IPv4 address
from `ipconfig`. Without configured settings, the launcher can reuse the last
saved address or prompt in an interactive terminal. You can also override it for
one launch:

```powershell
.\start-server.bat --address https://192.168.1.20:8443 --name Home
```

The default listening port follows the advertised URL (443 if it has no explicit
port), or the `CARRIEX_PORT` setting. Permit that inbound TCP port in your firewall for
the networks you intend to serve. Keep the terminal running. This Windows launcher
uses Flask's threaded development server with debugging disabled, suitable for
development/testing. Use the Docker/Gunicorn option below for a deployed service.

1. Open `.carriex-server\pairing.html` locally in your browser. The terminal prints
   its full path. It displays the QR and selectable pairing text.
2. On the phone, choose **Scan server QR**, grant camera access, then **Save server**.
   Alternatively choose **Import pairing text**, paste the whole JSON from the
   page or `pairing.json`, choose **Review**, then **Save server**.
3. Select **Connect** beside the saved server. Repeat pairing once on each phone.
4. Show **My ID QR** to a friend on the same server. They use **Scan friend's ID**
   to open a chat. **Verify friend's ID** inside a chat compares it with the
   friend's QR. The chat screen shows connection/reconnection status.

The scanner is built into Carriex. Text import works without camera permission.
Only import a bundle obtained directly from the server owner through a trusted
channel. An attacker who replaces the initial QR/text could substitute their own
server. The displayed fingerprint lets you compare the server key with the owner.
The bundle is public information, not an invitation password: device enrollment
is currently open to anyone who can reach the server and prove ownership of a key.

## Reaching the server from another network

Pairing establishes trust; the advertised address must still be reachable:

- **Same Wi-Fi:** advertise the home machine's LAN IP, such as
  `https://192.168.1.20:8443`. A router DHCP reservation keeps that IP stable.
- **Mobile data / another home:** advertise your router's public IP and external
  port, such as `https://203.0.113.10:8443` (documentation example only). Forward
  that TCP port on the router to the server machine's LAN IP and listening port,
  and permit it through the machine firewall. Test from mobile data; some routers
  cannot reach their own public address from inside the LAN.
- **ISP CGNAT or blocked inbound connections:** home port forwarding may not work.
  Obtain a reachable public IP from the ISP or move the server to a reachable host
  such as a VPS. Phones still need only Carriex. A changing public IP requires
  updating the advertised address and reimporting its bundle; optional dynamic DNS
  can give it a stable hostname.

The `--address` port is the one phones reach. The local listening port follows it
unless overridden with `--port` or `CARRIEX_LISTEN_PORT`, for a router mapping.
Startup clearly prints both when they differ. Never put
`0.0.0.0` or `localhost` in a bundle intended for another device. For an Android
emulator on the server machine, advertise `https://10.0.2.2:8443`.

## Key persistence and changes

Keep `.carriex-server` private and back it up securely. **Never share
`server-key.pem`**. Only `pairing.json`, `pairing.png`, and `pairing.html` are public;
copy the HTML and PNG together to display the page elsewhere. Do not publish the
whole identity directory. The launcher restricts directory permissions to the
launching account (and SYSTEM on Windows); use the same account on later starts.

The key is reused across restarts. The certificate lasts one year and renews on
startup when fewer than 30 days remain, using the same key. Restart before expiry;
there is no scheduled renewal of a continuously running process. Existing phones
accept a valid renewed certificate with that key without pairing again. Live
certificate dates and the requested hostname/IP remain checked.

To change the reachable address, edit `.env` and restart, keeping the same
identity directory, and distribute the new bundle. The server regenerates the
certificate's address entry using the existing key. Only the advertised address
is supported as the authentication origin at a time. Old address entries can be
forgotten on phones. To move to another machine, securely transfer the identity
directory and restrict its permissions there.

If a saved key disappears, startup fails instead of silently replacing the server
identity. Restore the backup. An intentionally new identity needs a new empty
`--data-dir`; phones must explicitly **Forget** the old entry before importing a
different key at the same address. A failed TLS connection never updates the pin.

Use `--pair-only` to generate/update pairing files without starting the listener.
Use `--check-config` to validate and print settings without modifying identity
files. `--config path/to/file.env` selects a different settings file. Precedence is
CLI overrides, shell environment, `.env`, then legacy saved settings. Relative
identity paths resolve from the working directory; the .bat/.sh launchers change
to their own folder. No parent directories are searched for .env files. Values
are literal; variable expansion and shell execution are not supported.

`--init-config` adds missing HOST/PORT/name settings based on the saved address or
an explicit `--address`, without changing existing values or creating keys. Legacy
`CARRIEX_PUBLIC_URL` remains supported as an alternative to HOST/PORT; do not set
both address forms. Legacy `CARRIEX_TLS_PORT` is a listening-port override.
Browser warnings when opening the HTTPS API are expected: the private trust is
inside Carriex. No system/browser certificate installation is needed.

## Docker / Linux

The standalone paired Compose file terminates TLS directly and uses a persistent
identity volume. From PowerShell:

```powershell
# First edit .env as described in README.md.
docker compose -f compose.paired.yaml up --build -d
docker compose -f compose.paired.yaml logs server
New-Item -ItemType Directory -Force pairing-export
docker compose -f compose.paired.yaml cp server:/var/lib/carriex/pairing.html ./pairing-export/
docker compose -f compose.paired.yaml cp server:/var/lib/carriex/pairing.png ./pairing-export/
docker compose -f compose.paired.yaml cp server:/var/lib/carriex/pairing.json ./pairing-export/
```

Open `pairing-export/pairing.html`. The published port defaults to 8443; set
`CARRIEX_PORT` in `.env` to change it. Preserve the `server-identity` volume; do not use
`docker compose down -v` unless intentionally deleting the identity. Back up the
private volume securely. Default `docker compose` includes this paired file;
`compose.proxy.yaml` is the separate old HTTP reverse-proxy deployment. Docker's
internal listener remains 8443; the configured host port maps to it automatically.

For native Linux, install `python -m pip install '.[server]'` and run
`python -m src.pairing --address https://YOUR_REACHABLE_IP:8443`. Linux uses one
Gunicorn worker with 100 threads. Keep one worker/replica: device registrations,
sessions, queues, and WebSockets remain in memory. Restart loses pending messages;
device authentication re-enrolls the same key-derived ID automatically. Internet
deployments still need operational rate limits and monitoring.
