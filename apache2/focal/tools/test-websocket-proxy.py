#!/usr/bin/env python3
"""Exercise Focal Apache mod_proxy_wstunnel with a local WebSocket upgrade."""
import base64
import hashlib
import socket
import sys
import time
from pathlib import Path

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CONF = Path("/etc/apache2/conf-available/unibo-websocket.conf")
KEY = "dGhlIHNhbXBsZSBub25jZQ=="
EXPECTED_ACCEPT = base64.b64encode(
    hashlib.sha1((KEY + GUID).encode("ascii")).digest()
).decode("ascii")

def configure():
    CONF.write_text(
        "ProxyPass /unibo-ws/ ws://127.0.0.1:19090/\n"
        "ProxyPassReverse /unibo-ws/ ws://127.0.0.1:19090/\n"
    )
    Path("/etc/apache2/conf-enabled/unibo-websocket.conf").symlink_to(CONF)

def read_headers(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed before HTTP header")
        buf += chunk
        if len(buf) > 16384:
            raise RuntimeError("Oversized HTTP header")
    return buf

def server():
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 19090))
        listener.listen(1)
        listener.settimeout(25)
        with listener.accept()[0] as client:
            client.settimeout(5)
            request = read_headers(client).decode("iso-8859-1")
            assert request.startswith("GET / HTTP/1.1"), request[:140]
            assert "upgrade: websocket" in request.lower(), request
            client.sendall(
                ("HTTP/1.1 101 Switching Protocols\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Accept: " + EXPECTED_ACCEPT + "\r\n\r\n"
                ).encode("ascii") + b"\x81\x05hello"
            )
            time.sleep(0.3)

def verify():
    request = (
        "GET /unibo-ws/ HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: " + KEY + "\r\n\r\n"
    ).encode("ascii")
    for attempt in range(20):
        try:
            sock = socket.create_connection(("127.0.0.1", 80), timeout=3)
            break
        except OSError:
            if attempt == 19:
                raise
            time.sleep(0.2)
    with sock:
        sock.settimeout(8)
        sock.sendall(request)
        response = read_headers(sock)
        head, remaining = response.split(b"\r\n\r\n", 1)
        assert head.startswith(b"HTTP/1.1 101 "), head[:180]
        assert ("sec-websocket-accept: " + EXPECTED_ACCEPT).encode().lower() in head.lower(), head
        while len(remaining) < 7:
            chunk = sock.recv(7 - len(remaining))
            if not chunk:
                raise RuntimeError("No WebSocket data frame")
            remaining += chunk
        assert remaining[:7] == b"\x81\x05hello", remaining
        print("PASS: WebSocket upgrade and backend-to-client frame via proxy_wstunnel")

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("configure", "server", "verify"):
        sys.exit("Usage: test-websocket-proxy.py configure|server|verify")
    if sys.argv[1] == "configure":
        configure()
    elif sys.argv[1] == "server":
        server()
    else:
        verify()
