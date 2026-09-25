"""Create a persistent TLS identity and an offline QR/text pairing bundle.

Run: python -m src.pairing --address https://192.168.1.20:8443 --name Home
Windows uses the threaded development server; Linux uses single-worker Gunicorn.
"""
import argparse
import base64
import csv
import hashlib
import html
import io
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import qrcode
from dotenv import set_key

from src.config import host_address, port_number, read_config


def canonical_address(value):
    if not isinstance(value, str) or len(value) > 512 or "\\" in value or any(c.isspace() for c in value):
        raise ValueError("Enter a complete HTTPS address without spaces")
    url = urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None:
        raise ValueError("Pairing requires an HTTPS address, for example https://192.168.1.20:8443")
    if url.path not in ("", "/") or url.query or url.fragment:
        raise ValueError("The server address must not contain a path, query, or fragment")
    port = 443 if url.port is None else url.port
    if not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    host = url.hostname.encode("idna").decode("ascii").lower()
    try:
        address = ipaddress.ip_address(host)
        if address.is_unspecified or address.is_multicast:
            raise ValueError("Use an address phones can connect to, not a bind/wildcard address")
        host = address.compressed
        if address.version == 6:
            host = f"[{host}]"
    except ValueError:
        if ":" in host or host in ("0.0.0.0", "::"):
            raise ValueError("Invalid server address") from None
        # An IP rejected above must not be reinterpreted as a DNS name.
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("Use a unicast, reachable server address") from None
        if not all(part and len(part) <= 63 and part[0] != "-" and part[-1] != "-"
                   and all(c.isascii() and (c.isalnum() or c == "-") for c in part)
                   for part in host.split(".")):
            raise ValueError("Invalid server hostname")
    authority = host if port == 443 else f"{host}:{port}"
    return urlunsplit(("https", authority, "", "", ""))


def private_directory(directory):
    if directory.exists() and any(directory.iterdir()) and not (directory / "identity-created").exists():
        raise ValueError("Choose an empty identity directory or an existing Carriex identity directory")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        # chmod alone does not restrict Windows ACLs. Grant only the launching
        # Windows account and SYSTEM access to the identity directory.
        result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                                capture_output=True, text=True, check=True)
        sid = next(csv.reader([result.stdout.strip()]))[1]
        subprocess.run(["icacls", str(directory), "/inheritance:r", "/grant:r",
                        f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                       capture_output=True, check=True)
    else:
        directory.chmod(0o700)


def atomic_write(path, value, mode=0o600):
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def pairing_export_directory(value, identity_directory, create=False):
    if value is None:
        return None
    if not value.strip():
        raise ValueError("CARRIEX_PAIRING_EXPORT_DIR must name a directory")
    destination = Path(value).expanduser().resolve()
    if destination == identity_directory or identity_directory in destination.parents:
        raise ValueError("Pairing export directory must be outside the private identity directory")
    if destination.exists() and not destination.is_dir():
        raise ValueError(f"Pairing export path is not a directory: {destination}")
    if create:
        destination.mkdir(parents=True, exist_ok=True)
    return destination


def prepare_pairing(directory, address, name="Carriex server", export_directory=None):
    directory = Path(directory).resolve()
    address = canonical_address(address)
    if not isinstance(name, str) or not name.strip() or len(name) > 80 or any(ord(c) < 32 for c in name):
        raise ValueError("Server name must contain 1-80 printable characters")
    name = name.strip()
    private_directory(directory)
    key_file = directory / "server-key.pem"
    cert_file = directory / "server-cert.pem"
    marker = directory / "identity-created"
    if not key_file.exists():
        if marker.exists() or cert_file.exists() or (directory / "pairing.json").exists():
            raise ValueError("The saved server key is missing. Restore it from backup; identity was not replaced")
        key = ec.generate_private_key(ec.SECP256R1())
        # Exclusive creation prevents two simultaneous starts replacing the key.
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("Saved TLS identity is not a P-256 key")
    atomic_write(marker, b"Preserve server-key.pem to preserve this server's identity.\n")
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hashlib.sha256(public).hexdigest()
    host = urlsplit(address).hostname
    try:
        alternative = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        alternative = x509.DNSName(host)
    now = datetime.now(timezone.utc)
    certificate = None
    if cert_file.exists():
        certificate = x509.load_pem_x509_certificate(cert_file.read_bytes())
        if certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != public:
            raise ValueError("Saved certificate and server key do not match; refusing identity replacement")
        certificate.verify_directly_issued_by(certificate)
        if (alternative not in certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                or certificate.not_valid_after_utc < now + timedelta(days=30)):
            certificate = None
    if certificate is None:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Carriex paired server")])
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
                       .add_extension(x509.SubjectAlternativeName([alternative]), critical=False)
                       .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                       .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                   key_encipherment=False, data_encipherment=False,
                                                   key_agreement=False, key_cert_sign=False, crl_sign=False,
                                                   encipher_only=False, decipher_only=False), critical=True)
                       .sign(key, hashes.SHA256()))
        atomic_write(cert_file, certificate.public_bytes(serialization.Encoding.PEM))
    bundle = {"type": "carriex-server", "version": 1, "name": name, "url": address,
              "certificate": base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode("ascii")}
    text = json.dumps(bundle, ensure_ascii=True, separators=(",", ":"))
    pairing_json = text.encode("utf-8")
    atomic_write(directory / "pairing.json", pairing_json)
    atomic_write(directory / "settings.json", json.dumps({"address": address, "name": name}).encode("utf-8"))
    code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
    code.add_data(text)
    code.make(fit=True)
    image = io.BytesIO()
    code.make_image(fill_color="black", back_color="white").save(image, format="PNG")
    pairing_png = image.getvalue()
    atomic_write(directory / "pairing.png", pairing_png)
    page = f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Pair {html.escape(name)}</title>
<style>body{{font:17px system-ui;max-width:850px;margin:40px auto;padding:0 20px;background:#f5f7fb;color:#162238}}
img{{width:100%;max-width:600px;image-rendering:pixelated}}textarea{{width:100%;height:140px;box-sizing:border-box}}
code{{overflow-wrap:anywhere}}button{{padding:12px;margin:12px 0}}</style>
<h1>{html.escape(name)}</h1><p><strong>{html.escape(address)}</strong></p>
<p>In Carriex, choose <strong>Scan server QR</strong>, or paste the text below using <strong>Import pairing text</strong>.</p>
<img src="pairing.png" alt="Carriex server pairing QR code">
<p>Server fingerprint: <code>{fingerprint}</code></p>
<textarea id="pairing" readonly aria-label="Pairing text">{html.escape(text)}</textarea>
<button onclick="document.getElementById('pairing').select()">Select pairing text</button>
<p>This bundle contains only the public certificate. Share it through a trusted channel.
Keep <code>server-key.pem</code> private and backed up. The address must be reachable from the phone.</p></html>'''
    pairing_html = page.encode("utf-8")
    atomic_write(directory / "pairing.html", pairing_html)
    if export_directory is not None:
        for filename, contents in (("pairing.json", pairing_json), ("pairing.png", pairing_png),
                                   ("pairing.html", pairing_html)):
            atomic_write(export_directory / filename, contents, mode=0o644)
    return bundle, fingerprint


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=".env", help="Settings file (default: .env in the working folder)")
    parser.add_argument("--address", help="HTTPS URL phones will use; its port is also listened on unless --port is supplied")
    parser.add_argument("--name")
    parser.add_argument("--data-dir")
    parser.add_argument("--pairing-export-dir", help="Existing folder for an additional copy of public pairing files")
    parser.add_argument("--bind", help="Listening interface, not the pairing address")
    parser.add_argument("--port", type=int, help="Override listening port for router/container port mapping")
    parser.add_argument("--check-config", action="store_true", help="Validate and display settings without changing keys or starting")
    parser.add_argument("--init-config", action="store_true", help="Add paired settings to .env from the saved address or --address")
    parser.add_argument("--pair-only", action="store_true", help="Generate QR/text without starting a listener")
    args = parser.parse_args(argv)
    try:
        config = read_config(args.config)
        directory = Path(args.data_dir or config.get("CARRIEX_IDENTITY_DIR") or ".carriex-server").resolve()
        export_directory = pairing_export_directory(
            args.pairing_export_dir if args.pairing_export_dir is not None else config.get("CARRIEX_PAIRING_EXPORT_DIR"),
            directory)
        settings = json.loads((directory / "settings.json").read_text("utf-8")) if (directory / "settings.json").exists() else {}
        configured_address = config.get("CARRIEX_PUBLIC_URL")
        if config.get("CARRIEX_HOST"):
            if configured_address:
                raise ValueError("Use CARRIEX_HOST + CARRIEX_PORT or CARRIEX_PUBLIC_URL, not both")
            configured_address = host_address(config["CARRIEX_HOST"], port_number(config.get("CARRIEX_PORT", "8443"), "CARRIEX_PORT"))
        elif "CARRIEX_PORT" in config and not configured_address and args.address is None:
            raise ValueError("Set CARRIEX_HOST together with CARRIEX_PORT")
        address = args.address if args.address is not None else configured_address or settings.get("address")
        if not address and sys.stdin.isatty():
            address = input("Address phones will use (e.g. https://192.168.1.20:8443): ").strip()
        if not address:
            parser.error("Set CARRIEX_HOST and CARRIEX_PORT in .env, or supply --address https://YOUR_IP:8443")
        address = canonical_address(address)
        public_port = urlsplit(address).port or 443
        listen_port = port_number(args.port if args.port is not None else
                                 config.get("CARRIEX_LISTEN_PORT") or config.get("CARRIEX_TLS_PORT") or public_port,
                                 "Listening port")
        bind = args.bind or config.get("CARRIEX_BIND") or "0.0.0.0"
        ipaddress.ip_address(bind)
        name = args.name if args.name is not None else config.get("CARRIEX_SERVER_NAME", settings.get("name", "Carriex server"))
        if not name.strip() or len(name) > 80 or any(ord(c) < 32 for c in name):
            raise ValueError("Server name must contain 1-80 printable characters")
        print(f"Config: {Path(args.config).resolve()}\nServer: {address}\nListening: {bind}:{listen_port}\nPrivate identity directory: {directory}", flush=True)
        if export_directory is not None:
            print(f"Public pairing export directory: {export_directory}", flush=True)
            if not export_directory.exists():
                print("Public pairing export directory will be created on startup.", flush=True)
        if listen_port != public_port:
            print(f"Port mapping required: phones reach {public_port}; this process listens on {listen_port}.", flush=True)
        if args.check_config:
            return
        if args.init_config:
            if config.get("CARRIEX_PUBLIC_URL"):
                raise ValueError("Remove CARRIEX_PUBLIC_URL before migrating to HOST/PORT settings")
            for key, value in {"CARRIEX_HOST": urlsplit(address).hostname,
                               "CARRIEX_PORT": str(public_port), "CARRIEX_SERVER_NAME": name}.items():
                if key not in config:
                    set_key(args.config, key, value)
            print("Paired settings added to .env. Review it before starting.", flush=True)
            return
        if export_directory is not None:
            export_directory = pairing_export_directory(str(export_directory), directory, create=True)
        bundle, fingerprint = prepare_pairing(directory, address, name, export_directory)
        print(f"Server: {bundle['url']}\nFingerprint: {fingerprint}\n"
              f"Open QR: {directory / 'pairing.html'}\nPairing text: {directory / 'pairing.json'}", flush=True)
        if export_directory is not None:
            print(f"Public pairing copy: {export_directory / 'pairing.html'} (with pairing.png and pairing.json)", flush=True)
        if args.pair_only:
            return
        # Paired mode terminates TLS itself. It never accepts spoofed forwarded
        # headers or enables the development HTTP bypass.
        os.environ["CARRIEX_AUTH_ORIGIN"] = bundle["url"]
        os.environ["CARRIEX_ALLOW_INSECURE_HTTP"] = "0"
        os.environ["CARRIEX_TRUST_PROXY"] = "0"
        os.environ["CARRIEX_DATA_DIR"] = str(directory)
        if config.get("CARRIEX_MESSAGE_TTL_SECONDS"):
            os.environ["CARRIEX_MESSAGE_TTL_SECONDS"] = config["CARRIEX_MESSAGE_TTL_SECONDS"]
        cert, key = str(directory / "server-cert.pem"), str(directory / "server-key.pem")
        if os.name != "nt":
            binding = f"[{bind}]:{listen_port}" if ":" in bind else f"{bind}:{listen_port}"
            os.execv(sys.executable, [sys.executable, "-m", "gunicorn", "--bind", binding,
                                     "--workers", "1", "--worker-class", "gthread", "--threads", "100",
                                     "--certfile", cert, "--keyfile", key, "src.app:app"])
        else:
            from src.app import create_app
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert, key)
            create_app().run(host=bind, port=listen_port, ssl_context=context,
                             threaded=True, debug=False, use_reloader=False)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Unable to start paired server: {exc}\n")


if __name__ == "__main__":
    main()
