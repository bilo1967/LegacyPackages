#!/usr/bin/env python3
"""Read-only audit of the nine failing Digest security patch hunks.

This tool must never apply any part of a security patch. It records full
upstream hunks and Focal source neighborhoods for manual rebasing.
"""
import pathlib
import re
import subprocess
import sys

if len(sys.argv) != 4:
    sys.exit("usage: audit-digest-port.py FOCAL_SOURCE PATCH OUTPUT_MD")
root, patch_path, destination = map(pathlib.Path, sys.argv[1:])
target = root / "modules/aaa/mod_auth_digest.c"
if not target.is_file() or not patch_path.is_file():
    sys.exit("Digest source or patch not found")
patch = patch_path.read_text(errors="replace")
source_lines = target.read_text(errors="replace").splitlines()
run = subprocess.run(
    ["patch", "--batch", "--forward", "--fuzz=0", "--dry-run", "-p1",
     "-i", str(patch_path)],
    cwd=str(root), text=True, stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT, timeout=60,
)
failed = set(int(number) for number in re.findall(
    r"Hunk #(\d+) FAILED", run.stdout
))
if run.returncode == 0 or not failed:
    sys.exit("Unexpected Digest patch outcome; audit must fail closed: " + run.stdout)
# The upstream patch may modify config.m4 first. Keep hunk numbering for the
# source file separate from config.m4 numbering.
start = patch.find("--- a/modules/aaa/mod_auth_digest.c")
if start < 0:
    sys.exit("Digest source patch section missing")
end = patch.find("\ndiff --git ", start + 5)
segment = patch[start:end if end >= 0 else len(patch)]
hunk_pattern = re.compile(r"(?m)^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n")
matches = list(hunk_pattern.finditer(segment))
if len(matches) < max(failed):
    sys.exit("Digest hunk count insufficient: %s vs %s" % (len(matches), max(failed)))
out = [
    "# CVE-2026-7363X: Focal Digest porting audit",
    "",
    "Experimental diagnostic only. **Not a CVE fix.**",
    "Patch must be ported and validated as a whole; no partial hunk application.",
    "",
    "Exact zero-fuzz dry run:",
    "",
    "```text",
    run.stdout.strip(),
    "```",
    "",
    "Failed mod_auth_digest.c hunks: " + ", ".join(map(str, sorted(failed))),
    "",
]
for n in sorted(failed):
    hunk = matches[n - 1]
    next_pos = matches[n].start() if n < len(matches) else len(segment)
    body = segment[hunk.start():next_pos].rstrip("\n")
    original_line = int(hunk.group(1))
    lo = max(1, original_line - 22)
    hi = min(len(source_lines), original_line + 40)
    out.extend([
        "## Upstream hunk #%d (old source line %d)" % (n, original_line),
        "",
        "```diff",
        body,
        "```",
        "",
        "Focal source nearby (line numbers are only an approximation):",
        "",
        "```text",
    ])
    out.extend("%5d %s" % (i, source_lines[i - 1])
               for i in range(lo, hi + 1))
    out.extend(["```", ""])
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text("\n".join(out) + "\n")
print("Wrote read-only Digest porting audit:", destination, "hunks", sorted(failed))
