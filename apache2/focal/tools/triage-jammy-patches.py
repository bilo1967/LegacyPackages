#!/usr/bin/env python3
"""Non-mutating first-pass applicability checks for Jammy quilt patches on Focal.

A clean dry run is NOT proof of CVE remediation; patch ordering, prerequisite
patches, regression fixes, and security applicability still require review.
"""
import pathlib
import re
import subprocess
import sys

if len(sys.argv) != 4:
    sys.exit("usage: triage-jammy-patches.py FOCAL_SOURCE JAMMY_SOURCE OUTPUT")
focal, jammy, out = (pathlib.Path(s).resolve() for s in sys.argv[1:])
out.mkdir(parents=True, exist_ok=True)

def patch_names(source):
    return [
        line.split()[0]
        for raw in (source / "debian/patches/series").read_text().splitlines()
        if (line := raw.strip()) and not line.startswith("#")
    ]

focal_names = set(patch_names(focal))
candidates = [n for n in patch_names(jammy) if n not in focal_names]
results = []
for name in candidates:
    patch_file = jammy / "debian/patches" / name
    if not patch_file.is_file():
        results.append((name, "MISSING", "File not found"))
        continue
    try:
        p = subprocess.run(
            ["patch", "--batch", "--forward", "--dry-run", "--fuzz=0",
             "-p1", "-i", str(patch_file)],
            cwd=focal, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=45,
        )
        output = p.stdout
        status = "DRY_RUN_OK" if p.returncode == 0 else "NEEDS_REVIEW"
        if "Reversed (or previously applied)" in output or "previously applied" in output:
            status = "POSSIBLY_APPLIED"
        lines = output.strip().splitlines()
        message = "; ".join(lines[-4:])[:400] if lines else "(no output)"
        results.append((name, status, message))
    except subprocess.TimeoutExpired:
        results.append((name, "TIMEOUT", "patch dry-run exceeded 45 seconds"))

with (out / "applicability.md").open("w") as f:
    f.write("# Jammy patches against Focal 2.4.41 (independent dry runs)\n\n")
    f.write("**Not a security validation.** All checks run independently against the unmodified, already-patched Focal source. A failure may reflect missing prerequisite patches; success does not establish functionality, patch order, CVE coverage, or compatibility.\n\n")
    f.write(f"Patch candidates: {len(results)}\n\n")
    for status in ("DRY_RUN_OK", "POSSIBLY_APPLIED", "NEEDS_REVIEW", "MISSING", "TIMEOUT"):
        f.write(f"- {status}: {sum(r[1] == status for r in results)}\n")
    f.write("\n| Candidate | Result | Output excerpt |\n|---|---|---|\n")
    for name, status, message in results:
        message = message.replace("|", "\\|").replace("`", "'")
        f.write(f"| `{name}` | {status} | {message} |\n")
print("Wrote", out / "applicability.md")
