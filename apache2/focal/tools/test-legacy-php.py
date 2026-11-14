#!/usr/bin/env python3
"""Check released PHP 8.x mod_php execution under experimental Focal Apache."""
import http.client
import sys

expected = sys.argv[1]
if expected not in ("8.3", "8.4"):
    sys.exit("Expected PHP 8.3 or 8.4")

conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
try:
    conn.request("GET", "/unibo-php-test.php")
    response = conn.getresponse()
    data = response.read()
    assert response.status == 200, ("status", response.status, data)
    assert response.getheader("X-Unibo-PHP") == "php8", "PHP handler not executed"
    assert data.strip() == expected.encode(), ("wrong PHP version", data)
    assert b"<?php" not in data, "PHP source leaked"
    print("PASS: released PHP %s mod_php with patched Apache prefork" % expected)
finally:
    conn.close()
