#!/usr/bin/env python3
"""Basic RFC 2617 Digest authentication regression checks in disposable Focal CI.

This validates the existing challenge and credential flow, not CVE-2026-7363X.
"""
import hashlib
import http.client
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

REALM = "unibo-ci-digest"
USERNAME = "ci-digest-user"
PASSWORD = "ci-digest-password"
LOCATION = "/unibo-digest"
BASE = "http://127.0.0.1"


def configure():
    Path("/var/www/html/unibo-digest").write_text("unibo-digest-ok\n")
    ha1 = hashlib.md5(
        ("%s:%s:%s" % (USERNAME, REALM, PASSWORD)).encode("utf-8")
    ).hexdigest()
    Path("/etc/apache2/unibo-digest.passwd").write_text(
        "%s:%s:%s\n" % (USERNAME, REALM, ha1)
    )
    Path("/etc/apache2/conf-available/unibo-digest.conf").write_text(
        "<Location /unibo-digest>\n"
        "    AuthType Digest\n"
        "    AuthName %s\n" % REALM +
        "    AuthUserFile /etc/apache2/unibo-digest.passwd\n"
        "    Require valid-user\n"
        "</Location>\n"
    )
    Path("/etc/apache2/conf-enabled/unibo-digest.conf").symlink_to(
        "/etc/apache2/conf-available/unibo-digest.conf"
    )


def get_with_credentials(password):
    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(REALM, BASE, USERNAME, password)
    opener = urllib.request.build_opener(
        urllib.request.HTTPDigestAuthHandler(password_manager)
    )
    return opener.open(BASE + LOCATION, timeout=5)


def verify():
    for attempt in range(20):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
            try:
                conn.request("GET", LOCATION)
                response = conn.getresponse()
                status = response.status
                challenge = response.getheader("WWW-Authenticate", "")
                response.read()
            finally:
                conn.close()
            break
        except OSError:
            if attempt == 19:
                raise
            time.sleep(0.25)
    assert status == 401, ("expected challenge", status)
    assert challenge.startswith("Digest "), ("missing Digest challenge", challenge)
    assert ('realm="' + REALM + '"') in challenge, challenge
    with get_with_credentials(PASSWORD) as response:
        assert response.status == 200, ("valid credentials rejected", response.status)
        assert response.read() == b"unibo-digest-ok\n", "wrong authenticated content"
    try:
        with get_with_credentials("not-the-password") as response:
            raise AssertionError("invalid credentials accepted: %s" % response.status)
    except urllib.error.HTTPError as error:
        assert error.code == 401, ("wrong password status", error.code)
    print("PASS: mod_auth_digest challenge, authorized and denied requests")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("configure", "verify"):
        sys.exit("Usage: test-digest-auth.py configure|verify")
    if sys.argv[1] == "configure":
        configure()
    else:
        verify()
