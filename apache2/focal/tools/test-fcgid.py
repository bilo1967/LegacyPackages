#!/usr/bin/env python3
"""Test the Ubuntu Focal mod_fcgid binary against experimental Apache."""
import http.client
import subprocess
from pathlib import Path
import sys
import time

CGI_PATH = Path("/usr/lib/cgi-bin/unibo-test.fcgi")
CONF = Path("/etc/apache2/conf-available/unibo-fcgid.conf")

def configure():
    CGI_PATH.parent.mkdir(parents=True, exist_ok=True)
    source = CGI_PATH.with_suffix(".c")
    source.write_text(r"""
#include <fcgi_stdio.h>
int main(void) {
    while (FCGI_Accept() >= 0) {
        printf("Content-Type: text/plain\r\n");
        printf("X-Unibo-Fcgid: OK\r\n\r\n");
        printf("unibo-fcgid-ok\n");
        fflush(stdout);
    }
    return 0;
}
""")
    subprocess.run(
        ["cc", "-O2", "-Wall", "-Wextra", "-o", str(CGI_PATH),
         str(source), "-lfcgi"],
        check=True,
    )
    CGI_PATH.chmod(0o755)
    CONF.write_text(
        "ScriptAlias /unibo-fcgi/ /usr/lib/cgi-bin/\n"
        "<Directory /usr/lib/cgi-bin>\n"
        "    Options +ExecCGI\n"
        "    SetHandler fcgid-script\n"
        "    Require all granted\n"
        "</Directory>\n"
    )
    Path("/etc/apache2/conf-enabled/unibo-fcgid.conf").symlink_to(CONF)

def verify():
    for attempt in range(15):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
            try:
                conn.request("GET", "/unibo-fcgi/unibo-test.fcgi")
                response = conn.getresponse()
                status = response.status
                headers = dict((k.lower(), v) for k, v in response.getheaders())
                body = response.read()
            finally:
                conn.close()
            if status != 200:
                logs = Path("/var/log/apache2/error.log")
                print(logs.read_text(errors="replace")[-6000:] if logs.exists()
                      else "No Apache error log", file=sys.stderr)
            assert status == 200, (status, body)
            assert headers.get("x-unibo-fcgid") == "OK", headers
            assert body == b"unibo-fcgid-ok\n", body
            print("PASS: Ubuntu Focal mod_fcgid executes a FastCGI program")
            return
        except (OSError, http.client.HTTPException):
            if attempt == 14:
                raise
            time.sleep(0.2)

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("configure", "verify"):
        sys.exit("Usage: test-fcgid.py configure|verify")
    if sys.argv[1] == "configure":
        configure()
    else:
        verify()
