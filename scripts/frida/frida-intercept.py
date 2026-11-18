#!/usr/bin/env python3
"""
Frida Runner for Android 14+ Interception & Pinning Bypass
Connects via USB or remote device, launches app, injects unpinning script.
"""

import sys
import os
import argparse
import time

try:
    import frida
except ImportError:
    print("[!] Error: 'frida' python library is not installed.")
    print("    Install it via: pip install frida frida-tools")
    sys.exit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
UNPIN_SCRIPT_PATH = os.path.join(SCRIPT_DIR, "universal-unpin.js")

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[!] Error: {message['description']}")

def main():
    parser = argparse.ArgumentParser(description="Frida Android 14+ SSL Unpinning Injector")
    parser.add_argument("-p", "--package", required=True, help="Target application package name (e.g. com.example.app)")
    parser.add_argument("-s", "--spawn", action="store_true", help="Spawn a new process instance instead of attaching")
    parser.add_argument("-H", "--host", help="Remote Frida server host:port (optional)")
    args = parser.parse_args()

    if not os.path.exists(UNPIN_SCRIPT_PATH):
        print(f"[!] Error: Script {UNPIN_SCRIPT_PATH} not found.")
        sys.exit(1)

    with open(UNPIN_SCRIPT_PATH, "r", encoding="utf-8") as f:
        hook_code = f.read()

    print(f"[*] Connecting to device...")
    try:
        if args.host:
            device = frida.get_device_manager().add_remote_device(args.host)
        else:
            device = frida.get_usb_device(timeout=5)
    except Exception as e:
        print(f"[!] Could not connect to device: {e}")
        print("    Ensure your device has USB debugging enabled and frida-server is running.")
        sys.exit(1)

    print(f"[+] Connected to: {device.name}")

    if args.spawn:
        print(f"[*] Spawning {args.package}...")
        pid = device.spawn([args.package])
        session = device.attach(pid)
        script = session.create_script(hook_code)
        script.on('message', on_message)
        script.load()
        device.resume(pid)
        print(f"[+] Spawned & Hooked PID: {pid}. Process resumed.")
    else:
        print(f"[*] Attaching to running process {args.package}...")
        try:
            session = device.attach(args.package)
        except Exception:
            print(f"[*] App not running, falling back to spawn...")
            pid = device.spawn([args.package])
            session = device.attach(pid)
            script = session.create_script(hook_code)
            script.on('message', on_message)
            script.load()
            device.resume(pid)
            print(f"[+] Spawned & Hooked PID: {pid}")
            sys.stdin.read()
            return

        script = session.create_script(hook_code)
        script.on('message', on_message)
        script.load()
        print(f"[+] Hook injected successfully into {args.package}!")

    print("[*] Interception active. Press Ctrl+C to stop.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Detaching and exiting...")
        session.detach()

if __name__ == "__main__":
    main()
