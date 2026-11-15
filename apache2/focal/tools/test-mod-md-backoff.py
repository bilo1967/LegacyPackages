#!/usr/bin/env python3
"""Exercise the patched *source expression* for mod_md retry delay under UBSan."""
import pathlib
import re
import subprocess
import sys
import tempfile

if len(sys.argv) != 2:
    sys.exit("usage: test-mod-md-backoff.py PATCHED_FOCAL_SOURCE")
source = (pathlib.Path(sys.argv[1]) / "modules/md/mod_md_drive.c").read_text()
pattern = (r"delay\s*=\s*\(err_count\s*>=\s*11\)\s*\?\s*"
           r"apr_time_from_sec\(60\s*\*\s*60\)\s*:\s*"
           r"apr_time_from_sec\(5\s*<<\s*\(err_count\s*-\s*1\)\);")
matches = list(re.finditer(pattern, source))
if len(matches) != 1:
    sys.exit("Expected exactly one patched Focal mod_md delay expression")
expression = matches[0].group(0)
if not re.search(r"if\s*\(delay\s*>\s*apr_time_from_sec\(60\s*\*\s*60\)\)", source):
    sys.exit("Missing post-calculation backoff cap")
# This C test executes the exact patched assignment, with UBSan enabled.
# No ACME networking is used: just the vulnerable arithmetic boundary.
harness = """
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#define apr_time_from_sec(s) ((int64_t)(s) * INT64_C(1000000))
static int64_t delay_for_errors(int err_count) {
    int64_t delay = 0;
    if (err_count > 0) {
        %s
        if (delay > apr_time_from_sec(60*60)) delay = apr_time_from_sec(60*60);
    }
    return delay;
}
int main(void) {
    struct {int errors; int64_t seconds;} cases[] = {
        {0,0},{1,5},{2,10},{10,2560},{11,3600},{12,3600},
        {30,3600},{1000,3600},{INT_MAX,3600}
    };
    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        int64_t actual = delay_for_errors(cases[i].errors);
        int64_t expected = apr_time_from_sec(cases[i].seconds);
        if (actual != expected) {
            fprintf(stderr,"errors=%%d: got %%lld, expected %%lld\\n",
                    cases[i].errors,(long long)actual,(long long)expected);
            return 1;
        }
    }
    puts("mod_md bounded backoff: 9 edge cases OK (UBSan)");
    return 0;
}
""" % expression
with tempfile.TemporaryDirectory(prefix="md-backoff-") as directory:
    c = pathlib.Path(directory) / "backoff.c"
    binary = pathlib.Path(directory) / "backoff"
    c.write_text(harness)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
