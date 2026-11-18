#!/usr/bin/env python3
"""
HTTP Toolkit Connect QR & Config URL Generator
Generates ready-to-use connect URLs and QR codes for connecting any Android 14+ device
to a 24/7 HTTP Toolkit / Frida proxy server.
"""

import sys
import os
import json
import base64
import argparse
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def get_cert_fingerprint(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data)
    pub_der = cert.public_key().public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(pub_der).digest()).decode("utf-8")

def generate_connect_url(ip, port, fingerprint):
    proxy_info = {
        "addresses": [ip],
        "port": int(port),
        "localTunnelPort": None,
        "certFingerprint": fingerprint
    }
    data_str = json.dumps(proxy_info)
    b64 = base64.urlsafe_b64encode(data_str.encode("utf-8")).decode("utf-8").rstrip("=")
    return f"https://android.httptoolkit.tech/connect/?data={b64}"

def main():
    parser = argparse.ArgumentParser(description="Generate HTTP Toolkit Android Connect URL & QR")
    parser.add_argument("--ip", required=True, help="IP address or domain of the 24/7 proxy server")
    parser.add_argument("--port", type=int, default=8000, help="Proxy port (default: 8000)")
    parser.add_argument("--cert", default="server/certs/ca.crt", help="Path to CA certificate file (default: server/certs/ca.crt)")
    parser.add_argument("--fingerprint", help="Direct public key SHA-256 fingerprint (overrides --cert)")
    args = parser.parse_args()

    fingerprint = args.fingerprint
    if not fingerprint:
        if not os.path.exists(args.cert):
            print(f"[!] Certificate not found at {args.cert}.")
            print("    Please run the 24/7 server first to generate ca.crt or pass --fingerprint")
            sys.exit(1)
        fingerprint = get_cert_fingerprint(args.cert)

    url = generate_connect_url(args.ip, args.port, fingerprint)

    print("\n" + "=" * 60)
    print(" 🚀 HTTP TOOLKIT 24/7 ANDROID CONNECT CONFIG")
    print("=" * 60)
    print(f"Target Proxy: {args.ip}:{args.port}")
    print(f"Cert Fingerprint: {fingerprint}")
    print("\n👉 Android Connect URL:")
    print(f"\n{url}\n")
    print("=" * 60)
    print("How to connect your Android 14+ device:")
    print("1. Copy the URL above to your Android device clipboard.")
    print("2. Open the HTTP Toolkit Clone App on your Android device.")
    print("3. Tap 'Scan QR code' (or Paste from Clipboard).")
    print("4. The app will immediately recognize the proxy and activate the VPN!")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()
