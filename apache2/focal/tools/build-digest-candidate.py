#!/usr/bin/env python3
"""Build-only full Digest replacement candidate from the patched Jammy source.

Input Focal must already have been prepared by prepare-experimental.py.
Never changes the baseline workflow's packages and never claims CVE coverage.
"""
import difflib
import pathlib
import re
import subprocess
import sys

if len(sys.argv) != 4:
    sys.exit("usage: build-digest-candidate.py PREPARED_FOCAL PATCHED_JAMMY OUTPUT_DIR")
focal, jammy, out = (pathlib.Path(v).resolve() for v in sys.argv[1:])
out.mkdir(parents=True, exist_ok=True)
rel = pathlib.Path("modules/aaa/mod_auth_digest.c")
before = (focal / rel).read_text()
after = (jammy / rel).read_text()
if "check_and_record_nonce" not in after or "client_generate" not in after:
    sys.exit("Patched Jammy Digest security implementation not found")
if "check_and_record_nonce" in before:
    sys.exit("Focal already contains new nonce handling: stop for review")
# Focal headers do not provide the Jammy convenience comparator. Preserve
# its case-insensitive meaning by using the C library equivalent.
after = re.sub(r"\bap_cstr_casecmp\s*\(", "strcasecmp(", after)
# Every complete security-sensitive function stays sourced from Jammy.
for name in ("check_and_record_nonce", "client_generate", "client_exists",
             "note_digest_auth_failure"):
    if name not in after:
        sys.exit("Missing complete upstream implementation: " + name)
patch_text = "".join(difflib.unified_diff(
    before.splitlines(keepends=True), after.splitlines(keepends=True),
    fromfile="a/" + str(rel), tofile="b/" + str(rel), n=3,
))
if not patch_text:
    sys.exit("No replacement diff generated")
patch = focal / "debian/patches/unibo-digest-jammy-complete-candidate.patch"
patch.write_text(patch_text)
dry_run = subprocess.run(
    ["patch", "--batch", "--forward", "--fuzz=0", "--dry-run", "-p1", "-i", str(patch)],
    cwd=focal, capture_output=True, text=True, timeout=60
)
if dry_run.returncode:
    sys.exit("Candidate zero-fuzz dry run failed:\n" + dry_run.stdout + dry_run.stderr)
apply = subprocess.run(
    ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch)],
    cwd=focal, capture_output=True, text=True, timeout=60
)
if apply.returncode or (focal / rel).read_text() != after:
    sys.exit("Candidate application failed or source content mismatched")
with (focal / "debian/patches/series").open("a") as handle:
    handle.write("unibo-digest-jammy-complete-candidate.patch\n")
(out / "digest-complete-candidate.patch").write_text(patch_text)
(out / "digest-candidate-notes.txt").write_text(
    "UNREVIEWED complete patched Jammy mod_auth_digest.c replacement for Focal.\n"
    "Only ap_cstr_casecmp -> strcasecmp is automatically adapted.\n"
    "This is deliberately NOT marked a CVE fix and not production-ready.\n"
    "Review differences from Focal unrelated to the CVE before promotion.\n"
)
print("Prepared full Digest candidate quilt patch; no production changes")
