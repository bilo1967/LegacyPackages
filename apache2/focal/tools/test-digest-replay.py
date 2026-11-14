#!/usr/bin/env python3
"""Diagnostic baseline for Digest nonce-count replay against experimental Focal.

Does not assert that CVE-2026-7363X is fixed. The deliberately identical
authenticated request is sent twice to detect whether the old module accepts
a replay; this must be revisited after the complete security port.
"""
import hashlib
import http.client
import secrets
import urllib.request

HOST = "127.0.0.1"
PATH = "/unibo-digest"
USER = "ci-digest-user"
REALM = "unibo-ci-digest"
PASSWORD = "ci-digest-password"


def md5(value):
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def request(authorization=None):
    connection = http.client.HTTPConnection(HOST, 80, timeout=5)
    try:
        headers = {"Authorization": authorization} if authorization else {}
        connection.request("GET", PATH, headers=headers)
        result = connection.getresponse()
        status = result.status
        challenge = result.getheader("WWW-Authenticate", "")
        body = result.read()
        return status, challenge, body
    finally:
        connection.close()


def main():
    status, challenge, _ = request()
    assert status == 401, ("expected a challenge", status)
    assert challenge.startswith("Digest "), challenge
    # The same RFC 2617 header parser used by Python's Digest handler.
    attrs = urllib.request.parse_keqv_list(
        urllib.request.parse_http_list(challenge[len("Digest "):])
    )
    assert attrs.get("realm") == REALM, attrs
    assert attrs.get("algorithm", "MD5").lower() == "md5", attrs
    qop_values = [item.strip() for item in attrs.get("qop", "").split(",")]
    assert "auth" in qop_values, ("qop=auth unavailable", attrs)
    nonce = attrs["nonce"]
    opaque = attrs.get("opaque")
    nc = "00000001"
    cnonce = secrets.token_hex(12)
    ha1 = md5("%s:%s:%s" % (USER, REALM, PASSWORD))
    ha2 = md5("GET:%s" % PATH)
    response = md5("%s:%s:%s:%s:auth:%s" % (ha1, nonce, nc, cnonce, ha2))
    fields = [
        'username="%s"' % USER,
        'realm="%s"' % REALM,
        'nonce="%s"' % nonce,
        'uri="%s"' % PATH,
        'response="%s"' % response,
        "qop=auth",
        "nc=%s" % nc,
        'cnonce="%s"' % cnonce,
        "algorithm=MD5",
    ]
    if opaque:
        fields.append('opaque="%s"' % opaque)
    authorization = "Digest " + ", ".join(fields)
    first, _, first_body = request(authorization)
    assert first == 200 and first_body == b"unibo-digest-ok\n", (
        "initial Digest request not accepted", first, first_body
    )
    second, _, _ = request(authorization)
    assert second in (200, 401), ("unexpected duplicate request status", second)
    if second == 200:
        print("BASELINE: repeated identical Digest Authorization accepted (HTTP 200).")
        print("This is NOT proof that CVE-2026-7363X is fixed.")
    else:
        print("BASELINE: repeated identical Digest Authorization rejected (HTTP 401).")
        print("This alone does NOT establish CVE-2026-7363X remediation.")


if __name__ == "__main__":
    main()
