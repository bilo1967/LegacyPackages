#!/usr/bin/env python3
"""Disposable CI regression checks for Apache response headers after CVE-2024-42516."""
import http.client
import time

HOST = "127.0.0.1"
PATH = "/unibo-ci-test.txt"
EXPECTED = b"unibo-focal-http-headers\n"


def request(method, headers=None):
    conn = http.client.HTTPConnection(HOST, 80, timeout=5)
    try:
        conn.request(method, PATH, headers=headers or {})
        response = conn.getresponse()
        status = response.status
        header_list = response.getheaders()
        body = response.read()
        return status, header_list, body
    finally:
        conn.close()


def unique(headers, key):
    values = [value for name, value in headers if name.lower() == key.lower()]
    assert len(values) <= 1, "Duplicate %s header: %r" % (key, values)
    return values[0] if values else None


for attempt in range(20):
    try:
        status, headers, body = request("GET")
        break
    except (OSError, http.client.HTTPException):
        if attempt == 19:
            raise
        time.sleep(0.25)

assert status == 200, ("GET", status)
assert body == EXPECTED, ("GET body", body)
length = unique(headers, "Content-Length")
assert length is not None and int(length) == len(EXPECTED), ("GET length", length)
assert unique(headers, "Content-Type"), "GET missing Content-Type"
last_modified = unique(headers, "Last-Modified")
assert last_modified, "GET missing Last-Modified for conditional request"

status, headers, body = request("HEAD")
assert status == 200, ("HEAD", status)
assert body == b"", ("HEAD sent body", body)
assert unique(headers, "Content-Length") == length, "HEAD length differs from GET"
unique(headers, "Content-Type")

status, headers, body = request("GET", {"If-Modified-Since": last_modified})
assert status == 304, ("conditional GET", status)
assert body == b"", ("304 sent body", body)
for forbidden in ("Content-Length", "Transfer-Encoding", "Content-Type"):
    assert unique(headers, forbidden) is None, "304 has " + forbidden
assert unique(headers, "Last-Modified"), "304 missing Last-Modified"
print("PASS: HTTP GET, HEAD, 304 header/body regressions")
