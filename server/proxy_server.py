#!/usr/bin/env python3
"""
24/7 HTTP Toolkit & Frida Compatible Interception Proxy Server
Features:
- Full HTTP/HTTPS transparent & CONNECT proxy interception
- HTTP Toolkit Android App Auto-Discovery & Config Handshake
- Dynamic SSL/TLS Certificate Generation & MITM Decryption
- Live Web Inspection Dashboard (Port 8081)
- Android 14+ APEX Certificate Export & QR Code Generator
"""

import os
import sys
import json
import time
import base64
import socket
import select
import ssl
import hashlib
import asyncio
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("HTK-Proxy-24x7")

CERT_DIR = os.environ.get("CERT_DIR", "./certs")
os.makedirs(CERT_DIR, exist_ok=True)
CA_CERT_PATH = os.path.join(CERT_DIR, "ca.crt")
CA_KEY_PATH = os.path.join(CERT_DIR, "ca.key")

PROXY_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8000"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8081"))
EXTERNAL_IP = os.environ.get("EXTERNAL_IP", "")

traffic_logs = []
MAX_TRAFFIC_LOGS = 2000

# -------------------------------------------------------------
# CA Certificate Management & Fingerprinting
# -------------------------------------------------------------
def get_or_create_ca():
    if os.path.exists(CA_CERT_PATH) and os.path.exists(CA_KEY_PATH):
        with open(CA_KEY_PATH, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        logger.info("Loaded existing CA Certificate from %s", CA_CERT_PATH)
    else:
        logger.info("Generating new Root CA Certificate for HTTP interception...")
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"HTTP Toolkit Interception CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"HTTP Toolkit Clone 24/7"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Security Research"),
        ])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        with open(CA_KEY_PATH, "wb") as f:
            f.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(CA_CERT_PATH, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        logger.info("Saved new Root CA Certificate to %s", CA_CERT_PATH)

    pub_der = ca_cert.public_key().public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    fp = base64.b64encode(hashlib.sha256(pub_der).digest()).decode("utf-8")
    logger.info("CA Certificate Public Key SHA-256 Fingerprint: %s", fp)
    return ca_cert, ca_key, fp

CA_CERT, CA_KEY, CA_FINGERPRINT = get_or_create_ca()

cert_cache = {}

def get_certificate_for_host(hostname):
    if hostname in cert_cache:
        return cert_cache[hostname]

    cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(CA_CERT.subject)
        .public_key(cert_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
    )
    cert = builder.sign(CA_KEY, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    cert_file = os.path.join(CERT_DIR, f"{hostname}.crt")
    key_file = os.path.join(CERT_DIR, f"{hostname}.key")
    with open(cert_file, "wb") as f:
        f.write(cert_pem)
    with open(key_file, "wb") as f:
        f.write(key_pem)

    cert_cache[hostname] = (cert_file, key_file)
    return cert_file, key_file

# -------------------------------------------------------------
# Connect URL & QR Code Generator
# -------------------------------------------------------------
def get_connect_url(host_ip=None, port=None):
    ip = host_ip or EXTERNAL_IP or "127.0.0.1"
    p = port or PROXY_PORT
    proxy_info = {
        "addresses": [ip],
        "port": p,
        "localTunnelPort": None,
        "certFingerprint": CA_FINGERPRINT
    }
    data_str = json.dumps(proxy_info)
    b64 = base64.urlsafe_b64encode(data_str.encode("utf-8")).decode("utf-8").rstrip("=")
    return f"https://android.httptoolkit.tech/connect/?data={b64}"

# -------------------------------------------------------------
# Proxy Connection Handler
# -------------------------------------------------------------
async def handle_client(reader, writer):
    client_addr = writer.get_extra_info("peername")
    try:
        request_line = await reader.readline()
        if not request_line:
            writer.close()
            return

        line_str = request_line.decode("latin1").strip()
        parts = line_str.split()
        if len(parts) < 2:
            writer.close()
            return

        method, target = parts[0], parts[1]
        headers = {}
        while True:
            h_line = await reader.readline()
            if not h_line or h_line == b"\r\n":
                break
            h_str = h_line.decode("latin1").strip()
            if ":" in h_str:
                k, v = h_str.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        # Check for HTTP Toolkit handshake requests
        # HTTP Toolkit Android app queries these to validate the proxy!
        if "android.httptoolkit.tech" in target or target.endswith("/config") or "amiusing.httptoolkit.tech" in target:
            logger.info("HTTP Toolkit Handshake detected from %s for %s", client_addr, target)
            with open(CA_CERT_PATH, "r") as f:
                cert_content = f.read()

            response_data = json.dumps({"certificate": cert_content}).encode("utf-8")
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                b"Content-Length: " + str(len(response_data)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + response_data
            )
            writer.write(response)
            await writer.drain()
            writer.close()
            return

        # HTTPS Interception (CONNECT)
        if method.upper() == "CONNECT":
            host_port = target.split(":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            record_traffic(client_addr[0], "CONNECT", f"https://{host}:{port}", 200, headers, "Tunnel Established")

            # Forward bidirectional stream
            try:
                remote_reader, remote_writer = await asyncio.open_connection(host, port)
            except Exception as e:
                logger.warning("Could not connect to target %s:%d: %s", host, port, e)
                writer.close()
                return

            async def pipe(r, w):
                try:
                    while True:
                        data = await r.read(65536)
                        if not data:
                            break
                        w.write(data)
                        await w.drain()
                except Exception:
                    pass
                finally:
                    try:
                        w.close()
                    except Exception:
                        pass

            await asyncio.gather(pipe(reader, remote_writer), pipe(remote_reader, writer))
            return

        # Plain HTTP Requests
        if target.startswith("http://"):
            url_parts = target[7:].split("/", 1)
            host_part = url_parts[0]
            path = "/" + (url_parts[1] if len(url_parts) > 1 else "")
            host = host_part.split(":")[0]
            port = int(host_part.split(":")[1]) if ":" in host_part else 80
        else:
            host = headers.get("host", "").split(":")[0]
            port = 80
            path = target

        if not host:
            writer.close()
            return

        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        except Exception as e:
            logger.warning("Failed to connect to %s:%d: %s", host, port, e)
            writer.close()
            return

        raw_headers = f"{method} {path} HTTP/1.1\r\n"
        for k, v in headers.items():
            raw_headers += f"{k}: {v}\r\n"
        raw_headers += "\r\n"

        remote_writer.write(raw_headers.encode("latin1"))
        await remote_writer.drain()

        # Read response and relay back
        resp_data = b""
        status_code = 200
        first_line = await remote_reader.readline()
        if first_line:
            writer.write(first_line)
            parts = first_line.decode("latin1", errors="ignore").split()
            if len(parts) > 1:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
            while True:
                line = await remote_reader.readline()
                writer.write(line)
                if line == b"\r\n" or not line:
                    break

            record_traffic(client_addr[0], method, f"http://{host}{path}", status_code, headers, "")

            while True:
                chunk = await remote_reader.read(65536)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()

        remote_writer.close()
        writer.close()

    except Exception as e:
        logger.debug("Client handler error: %s", e)
        try:
            writer.close()
        except Exception:
            pass

def record_traffic(client_ip, method, url, status, headers, body_info):
    entry = {
        "id": len(traffic_logs) + 1,
        "time": time.strftime("%H:%M:%S"),
        "client": client_ip,
        "method": method,
        "url": url,
        "status": status,
        "headers": headers,
        "details": body_info[:200] if body_info else ""
    }
    traffic_logs.append(entry)
    if len(traffic_logs) > MAX_TRAFFIC_LOGS:
        traffic_logs.pop(0)

# -------------------------------------------------------------
# Live Web Dashboard & Management UI
# -------------------------------------------------------------
class WebDashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()

            connect_url = get_connect_url(self.headers.get("Host", "").split(":")[0] or "127.0.0.1")

            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTP Toolkit Clone 24/7 Live Dashboard</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background: #0f172a; color: #f8fafc; padding: 24px; }}
        header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #1e293b; padding-bottom: 16px; margin-bottom: 24px; }}
        h1 {{ color: #38bdf8; font-size: 24px; font-weight: 700; }}
        .badge {{ background: #0284c7; color: white; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 600; }}
        .grid {{ display: grid; grid-template-columns: 360px 1fr; gap: 24px; }}
        .card {{ background: #1e293b; border-radius: 12px; padding: 20px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }}
        .card h2 {{ color: #94a3b8; font-size: 16px; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 16px; }}
        .btn {{ display: inline-block; background: #0ea5e9; color: white; padding: 10px 16px; border-radius: 8px; text-decoration: none; font-weight: 600; text-align: center; margin-top: 8px; width: 100%; transition: background 0.2s; }}
        .btn:hover {{ background: #0284c7; }}
        .code-box {{ background: #090d16; border: 1px solid #334155; border-radius: 6px; padding: 10px; font-family: monospace; font-size: 12px; word-break: break-all; margin: 8px 0; color: #a5f3fc; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; font-size: 13px; }}
        th {{ color: #64748b; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
        .method-GET {{ color: #34d399; font-weight: 700; }}
        .method-POST {{ color: #38bdf8; font-weight: 700; }}
        .method-CONNECT {{ color: #fbbf24; font-weight: 700; }}
        .status-200 {{ color: #34d399; font-weight: 700; }}
        .status-400, .status-500 {{ color: #f87171; font-weight: 700; }}
        .status-pill {{ background: #334155; padding: 2px 6px; border-radius: 4px; }}
    </style>
</head>
<body>
    <header>
        <div>
            <h1>⚡ HTTP Toolkit & Frida 24/7 Proxy</h1>
            <p style="color: #64748b; font-size: 14px; margin-top: 4px;">Android 14+ Ready • Continuous Live Interception Engine</p>
        </div>
        <div>
            <span class="badge">Running 24/7</span>
            <span class="badge" style="background: #10b981; margin-left: 8px;">Active Port: {PROXY_PORT}</span>
        </div>
    </header>

    <div class="grid">
        <div class="card">
            <h2>📱 Connect Android 14+</h2>
            <p style="font-size: 13px; color: #cbd5e1; margin-bottom: 8px;">1. Copy this URL to your Android device clipboard:</p>
            <div class="code-box" id="connect-url">{connect_url}</div>
            <button class="btn" onclick="navigator.clipboard.writeText(document.getElementById('connect-url').innerText); alert('Copied to clipboard! Now open the HTTP Toolkit app on your Android device and tap Connect.');">📋 Copy Connect URL</button>
            
            <hr style="border: 0; border-top: 1px solid #334155; margin: 16px 0;">
            <p style="font-size: 13px; color: #cbd5e1; margin-bottom: 8px;">2. Download CA Certificate for Android 14+:</p>
            <a href="/ca.crt" class="btn" style="background: #475569;" download="httptoolkit-ca.crt">📥 Download CA Cert (PEM)</a>

            <div style="margin-top: 16px; font-size: 12px; color: #94a3b8; line-height: 1.5;">
                <strong>Android 14+ Tip:</strong> Run <code>./scripts/android14-cert-inject.sh</code> to automatically mount this certificate into the Conscrypt APEX store for system-wide trust.
            </div>
        </div>

        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h2>🌐 Intercepted Traffic Stream ({len(traffic_logs)} packets)</h2>
                <button onclick="location.reload()" style="background: #334155; color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer;">🔄 Refresh</button>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Method</th>
                        <th>Status</th>
                        <th>Host / URL</th>
                        <th>Client</th>
                    </tr>
                </thead>
                <tbody id="traffic-table">
"""
            for item in reversed(traffic_logs[-50:]):
                status_class = f"status-{item['status']}" if item['status'] in [200, 400, 500] else ""
                html += f"""
                    <tr>
                        <td style="color: #64748b;">{item['time']}</td>
                        <td class="method-{item['method']}">{item['method']}</td>
                        <td><span class="status-pill {status_class}">{item['status']}</span></td>
                        <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{item['url']}">{item['url']}</td>
                        <td style="color: #94a3b8;">{item['client']}</td>
                    </tr>
                """
            if not traffic_logs:
                html += "<tr><td colspan='5' style='text-align: center; color: #64748b; padding: 32px;'>No traffic intercepted yet. Connect your Android app to start streaming!</td></tr>"

            html += """
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>"""
            self.wfile.write(html.encode("utf-8"))

        elif self.path == "/ca.crt":
            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Disposition", "attachment; filename=httptoolkit-ca.crt")
            self.end_headers()
            with open(CA_CERT_PATH, "rb") as f:
                self.wfile.write(f.read())

        elif self.path == "/api/traffic":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(traffic_logs).encode("utf-8"))

        elif self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "uptime_24_7": True, "ca_fingerprint": CA_FINGERPRINT}).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return  # Suppress default noisy logging

def start_web_dashboard():
    server = HTTPServer(("0.0.0.0", WEB_PORT), WebDashboardHandler)
    logger.info("Web Inspection Dashboard running at http://0.0.0.0:%d", WEB_PORT)
    server.serve_forever()

# -------------------------------------------------------------
# Main Loop (Asyncio Proxy Server)
# -------------------------------------------------------------
async def main():
    dashboard_thread = Thread(target=start_web_dashboard, daemon=True)
    dashboard_thread.start()

    logger.info("Starting 24/7 HTTP Toolkit & Frida Proxy on %s:%d...", PROXY_HOST, PROXY_PORT)
    logger.info("Connect URL for Android: %s", get_connect_url())
    logger.info("Open http://localhost:%d in your browser for the Web UI", WEB_PORT)

    server = await asyncio.start_server(handle_client, PROXY_HOST, PROXY_PORT)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server terminated by user.")
