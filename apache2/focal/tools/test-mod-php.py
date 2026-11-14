#!/usr/bin/env python3
"""Smoke test Focal distro mod_php7.4 against experimental Apache in prefork."""
import http.client

conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
try:
    conn.request("GET", "/unibo-php-test.php")
    response = conn.getresponse()
    payload = response.read()
    assert response.status == 200, ("mod_php status", response.status, payload)
    assert response.getheader("X-Unibo-PHP") == "php74", "PHP module did not execute"
    assert payload.strip() == b"7.4", ("unexpected PHP version", payload)
    assert b"<?php" not in payload, "PHP source leaked"
    print("PASS: distro mod_php7.4 under Apache prefork")
finally:
    conn.close()
