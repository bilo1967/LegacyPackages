#!/usr/bin/env python3
"""Build a small out-of-tree Apache module with experimental Focal apxs and test it."""
import http.client
from pathlib import Path
import subprocess
import sys
import time

SOURCE = Path("/tmp/mod_unibo_abi.c")
MODULE = Path("/usr/lib/apache2/modules/mod_unibo_abi.so")
LOAD = Path("/etc/apache2/mods-available/unibo_abi.load")
CONF = Path("/etc/apache2/conf-available/unibo-abi.conf")


def configure():
    SOURCE.write_text(r"""
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"

static int unibo_abi_handler(request_rec *r) {
    if (!r->handler || strcmp(r->handler, "unibo-abi")) {
        return DECLINED;
    }
    ap_set_content_type(r, "text/plain");
    apr_table_set(r->headers_out, "X-Unibo-Apxs", "OK");
    if (!r->header_only) {
        ap_rputs("unibo-apxs-ok\n", r);
    }
    return OK;
}

static void unibo_abi_hooks(apr_pool_t *pool) {
    ap_hook_handler(unibo_abi_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA unibo_abi_module = {
    STANDARD20_MODULE_STUFF,
    NULL, NULL, NULL, NULL, NULL,
    unibo_abi_hooks
};
""")
    subprocess.run(["apxs", "-c", "-i", str(SOURCE)], check=True)
    if not MODULE.is_file():
        raise RuntimeError("apxs did not install the expected .so")
    LOAD.write_text("LoadModule unibo_abi_module " + str(MODULE) + "\n")
    subprocess.run(["a2enmod", "unibo_abi"], check=True)
    CONF.write_text(
        "<Location /unibo-abi>\n"
        "    SetHandler unibo-abi\n"
        "</Location>\n"
    )
    subprocess.run(["a2enconf", "unibo-abi"], check=True)


def verify():
    for attempt in range(15):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
            try:
                conn.request("GET", "/unibo-abi")
                response = conn.getresponse()
                status = response.status
                headers = dict((key.lower(), value) for key, value in response.getheaders())
                data = response.read()
            finally:
                conn.close()
            assert status == 200, (status, data)
            assert headers.get("x-unibo-apxs") == "OK", headers
            assert data == b"unibo-apxs-ok\n", data
            print("PASS: out-of-tree module compiled and executed with experimental apxs")
            return
        except (OSError, http.client.HTTPException):
            if attempt == 14:
                raise
            time.sleep(0.2)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("configure", "verify"):
        sys.exit("Usage: test-apxs-abi.py configure|verify")
    if sys.argv[1] == "configure":
        configure()
    else:
        verify()
