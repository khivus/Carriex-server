# Carriex Server

Run your own Carriex chat server, then connect phones by scanning its QR code.
You do not need to register a website or install another app on the phones.

## Message storage

The server saves opaque encrypted messages in `messages.sqlite3` inside its
private data directory (`.carriex-server` by default, `/var/lib/carriex` in the
paired Docker volume). Pending messages survive server restarts. They expire
after 30 days by default; set `CARRIEX_MESSAGE_TTL_SECONDS` in the server
environment to change this. Each recipient queue holds at most 1,000 messages.
The server deletes a message's ciphertext only after the recipient acknowledges
its ID, or when it expires. Fetching and WebSocket transmission alone do not
remove it. The sender can query its message states; a recipient can acknowledge
with `report_delivery: false` to clear the queue without revealing receipt.
The phone owns its saved chat history. Keep the private data volume when
recreating the server container.

## 1. Set your address and port

The settings file is **`.env` in this folder**, beside this README.
If it does not exist, copy `.env.example` and name the copy exactly `.env`
(not `.env.txt`). Open it in a text editor:

```dotenv
CARRIEX_HOST=192.168.0.34
CARRIEX_PORT=8443
CARRIEX_SERVER_NAME='Carriex-server'
```

- Replace the example IP with the computer's Wi-Fi/Ethernet IPv4 address.
  On Windows, run `ipconfig` to find it.
- `CARRIEX_HOST` contains only the IP or hostname: no `https://`, path, or port.
- `CARRIEX_PORT` is the port phones connect to and the port opened on your computer.
  Use `8443` or change it to `443`. With 443, the address is just
  `https://192.168.0.34`; with 8443 it is `https://192.168.0.34:8443`.
- `CARRIEX_SERVER_NAME` is the name displayed on phones.
- Optionally set `CARRIEX_PAIRING_EXPORT_DIR` to a
  folder for public `pairing.html`, `pairing.png`, and `pairing.json`
  copies. Docker needs the optional Compose export override; see
  [PAIRING.md](PAIRING.md).

Save the file. Restart the server after editing it. Startup checks the settings,
prints the address and listening port, and refreshes the QR/text. Address changes
also update the certificate when needed. **The private server identity key stays
the same**, so a configuration edit does not unexpectedly replace a trusted server.
After changing the address or port, import the updated QR on phones and forget
the obsolete address entry.

Old `HOST` / `PORT` entries are for the legacy HTTP proxy deployment and do not
configure the paired server. Use the three `CARRIEX_...` entries above.

## 2. Choose ONE way to start

All three options use the same `.env`.

### Windows: double-click a .bat file

Install Python 3.11 or newer. Open PowerShell in this folder and run once:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Then double-click **start-server.bat**, or run:

```powershell
.\start-server.bat
```

Leave the terminal open. Press Ctrl+C to stop. The native Windows launcher is for
development/home testing; Docker is the preferred option for a deployed service.

To check settings without starting the server:

```powershell
.\start-server.bat --check-config
```

### Linux / macOS: shell launcher

A `.bat` file does **not** run natively on Linux. Use the included shell script.
From this folder, install once:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[server]'
```

Start and leave the terminal open:

```sh
sh start-server.sh
```

Press Ctrl+C to stop. Check settings with `sh start-server.sh --check-config`.
Linux/macOS uses Gunicorn. If the OS refuses native port 443, use Docker's port
mapping or use 8443; do not run the whole app as root just to bind a port.

### Docker: Windows, Linux, or macOS

Install Docker with Docker Compose, start Docker, and open a terminal in this folder:

```sh
docker compose up --build -d
docker compose logs -f server
```

The server keeps running in the background. Ctrl+C only exits the log view.
After editing `.env`, apply the changes with `docker compose up -d`
(a simple `restart` does not reload changed container settings).
After updating server code, use `docker compose up --build -d`.

Stop it with:

```sh
docker compose down
```

**Do not add `-v`**: that deletes the volume containing your server's identity.
Docker maps `CARRIEX_PORT` on your computer to internal port 8443 automatically.
That internal port is normal and does not limit the port phones can use.

Already using `compose.paired.yaml`? It remains supported.
The old HTTP-only proxy setup is now explicitly `compose.proxy.yaml`.

## 3. Open the QR and connect phones

**Native .bat / .sh:** open `.carriex-server/pairing.html` in a browser.
The terminal also prints its complete path.

**Docker:** copy just the public pairing files to this folder:

```sh
docker compose cp server:/var/lib/carriex/pairing.html ./pairing.html
docker compose cp server:/var/lib/carriex/pairing.png ./pairing.png
docker compose cp server:/var/lib/carriex/pairing.json ./pairing.json
```

Open `pairing.html`. Keep the PNG beside the HTML. Copy these files again after
changing settings; an old exported page does not update itself.

On each phone:

1. Open Carriex and choose **Scan server QR**.
2. Scan the page, review the address, and select **Save server**, then **Connect**.
3. Without a camera, choose **Import pairing text** and paste the whole contents
   of `pairing.json` instead.
4. In Chats, show **My ID QR** to a friend. They choose **Scan friend's ID** to
   start your chat. Inside an existing chat, **Verify friend's ID** compares that
   conversation's ID with the QR on the friend's phone.

## Cannot connect?

- **Same Wi-Fi:** use the computer's LAN address and allow inbound TCP on
  `CARRIEX_PORT` in its firewall. Do not use `localhost` on another phone.
- **Different Wi-Fi or mobile data:** a LAN address such as `192.168...` is not
  reachable over the internet. Use your public IP and forward that router port to
  your computer. If your ISP uses CGNAT, ask for a public IP or use a reachable VPS.
  See [network setup](PAIRING.md#reaching-the-server-from-another-network).
- **Port 443 fails:** check startup's `Listening:` line. Check for another program
  already using 443 and a firewall rule for it. Native Linux may restrict low ports.
  The launcher now uses the URL/configured port instead of silently using 8443.
- **Server identity error:** check the phone's clock and import the current pairing
  address. Verify an intentional key change with the owner before forgetting an
  old trusted entry.
- **Configuration error:** startup tells you which setting needs fixing. Quoted
  names are supported. Values are literal; do not put shell commands in this file.

## Keep these files safe

Back up the native `.carriex-server` folder or Docker's `server-identity` volume.
Never share `server-key.pem`. Share only the pairing HTML, PNG, or JSON through a
trusted channel. A missing saved key causes startup to stop, not silently replace it.

Native and Docker storage are separate. Switching modes does not automatically
copy the identity; preserve/migrate its private storage if you need the same key.
See [identity and advanced setup](PAIRING.md), [authentication](AUTHENTICATION.md),
and [developer/API documentation](DEVELOPMENT.md).

Device sessions and pending messages are currently in memory and disappear when
the server restarts. Phones can authenticate again with the same device ID.
