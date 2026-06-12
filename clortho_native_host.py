#!/usr/bin/env python3
"""
Native messaging host for Clortho.
Firefox launches this to start the vault server on demand.
Protocol: 4-byte little-endian length prefix + UTF-8 JSON, both directions.
"""

import json
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path("PLACEHOLDER_PROJECT_DIR")
PORT = 7777
HOST = "127.0.0.1"


def read_message():
    raw = sys.stdin.buffer.read(4)
    if len(raw) < 4:
        return None
    return json.loads(sys.stdin.buffer.read(struct.unpack("<I", raw)[0]))


def send_message(obj):
    data = json.dumps(obj).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def server_running():
    try:
        s = socket.create_connection((HOST, PORT), timeout=1)
        s.close()
        return True
    except OSError:
        return False


def start_server():
    if server_running():
        return True
    subprocess.Popen(
        [sys.executable, str(SCRIPT_DIR / "clortho_web.py"), "--no-browser"],
        cwd=str(SCRIPT_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    for _ in range(20):
        time.sleep(0.4)
        if server_running():
            return True
    return False


msg = read_message()
if msg and msg.get("type") == "start_server":
    send_message({"ok": start_server()})
else:
    send_message({"ok": False, "error": "unknown command"})
