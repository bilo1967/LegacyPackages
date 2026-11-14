#!/usr/bin/env python3
"""Disposable Apache Focal TLS and mod_rewrite end-to-end regression test."""
import http.client
import pathlib
import ssl
import sys
import time
import urllib.parse

CERT = "/etc/ssl/certs/unibo-ci.pem"
EXPECTED = b"unibo-focal-http-headers\n"


def configure():
    # Server-context rewrite applies to both the default HTTP and HTTPS vhosts.
    conf = pathlib.Path("/etc/apache2/conf-available/unibo-rewrite.conf")
    conf.write_text(
        "<Directory /var/www/html>\n"
        "RewriteEngine On\n"
        "RewriteRule ^unibo-ci-old$ /unibo-ci-test.txt [R=302,L]\n"
        "</Directory>\n"
    )
    pathlib.Path("/etc/apache2/conf-enabled/unibo-rewrite.conf").symlink_to(conf)


def query(secure, path):
    if secure:
        context = ssl.create_default_context(cafile=CERT)
        conn = http.client.HTTPSConnection("localhost", 443, timeout=5, context=context)
    else:
        conn = http.client.HTTPConnection("localhost", 80, timeout=5)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        result = response.status, dict((k.lower(), v) for k, v in response.getheaders()), response.read()
        return result
    finally:
        conn.close()


def verify():
    for attempt in range(20):
        try:
            query(False, "/unibo-ci-test.txt")
            break
        except (OSError, http.client.HTTPException):
            if attempt == 19:
                raise
            time.sleep(0.25)
    for secure in (False, True):
        code, headers, body = query(secure, "/unibo-ci-test.txt")
        assert code == 200, ("GET", secure, code)
        assert body == EXPECTED, ("GET body", secure, body)
        code, headers, body = query(secure, "/unibo-ci-old")
        assert code == 302, ("rewrite redirect", secure, code, body)
        assert urllib.parse.urlsplit(headers.get("location", "")).path == "/unibo-ci-test.txt", headers
    print("PASS: HTTP and verified local TLS with mod_rewrite redirects")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("configure", "verify"):
        sys.exit("Usage: test-ssl-rewrite.py configure|verify")
    globals()[sys.argv[1]]()
