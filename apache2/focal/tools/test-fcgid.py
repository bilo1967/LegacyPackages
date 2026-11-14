#!/usr/bin/env python3
"""Test the Ubuntu Focal mod_fcgid binary against experimental Apache."""
import http.client
from pathlib import Path
import sys
import time

CGI_PATH = Path("/usr/lib/cgi-bin/unibo-test.fcgi")
CONF = Path("/etc/apache2/conf-available/unibo-fcgid.conf")

def configure():
    CGI_PATH.parent.mkdir(parents=True, exist_ok=True)
    CGI_PATH.write_text(
        "#!/usr/bin/python3\n"
        "import sys\n"
        "sys.stdout.write('Content-Type: text/plain\\r\\n')\n"
        "sys.stdout.write('X-Unibo-Fcgid: OK\\r\\n\\r\\n')\n"
        "sys.stdout.write('unibo-fcgid-ok\\n')\n"
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
            assert status == 200, (status, body)
            assert headers.get("x-unibo-fcgid") == "OK", headers
            assert body == b"unibo-fcgid-ok\n", body
            print("PASS: Ubuntu Focal mod_fcgid executes a CGI program")
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
