#!/usr/bin/env python3
"""Prepare an experimental Ubuntu Bionic Apache package with exactly two clean CVE patches.

The existing Debian quilt packaging is retained. The script refuses source
changes, context fuzz, offsets, missing files, or already-present patch names.
"""
from datetime import datetime, timezone
from pathlib import Path
import os
import shutil
import subprocess
import sys

if len(sys.argv) != 4:
    sys.exit("usage: prepare-two.py BIONIC_SOURCE JAMMY_PATCH_ROOT OUTPUT_REPORT")
src, ref, out = [Path(x).resolve() for x in sys.argv[1:]]
out.mkdir(parents=True, exist_ok=True)
candidates = ["CVE-2026-63292.patch", "CVE-2026-56153.patch"]
series_path = src / "debian/patches/series"
lines = series_path.read_text().splitlines()
existing = {l.strip().split()[0] for l in lines if l.strip() and not l.startswith("#")}
patch_dir = src / "debian/patches"
for name in candidates:
    if name in existing:
        sys.exit("Already present in Bionic patch series: " + name)
    reference = ref / "debian/patches" / name
    if not reference.is_file():
        sys.exit("Jammy patch not found: " + str(reference))
    # Confirm that a pristine Bionic source tree accepts the patch as-is.
    p = subprocess.run(
        ["patch", "--dry-run", "--batch", "--fuzz=0", "-p1", "-i", str(reference)],
        cwd=src, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=30)
    if p.returncode != 0 or "offset " in p.stdout or "fuzz " in p.stdout:
        sys.exit("Refusing candidate requiring a port: " + name + "\n" + p.stdout)
    shutil.copy2(reference, patch_dir / name)
    series_path.write_text(series_path.read_text().rstrip("\n") + "\n" + name + "\n")
    # Apply through quilt so dpkg-source state and packaging remain consistent.
    q = subprocess.run(["quilt", "push", "-a"], cwd=src, universal_newlines=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, "QUILT_PATCHES": "debian/patches",
             "QUILT_PATCH_OPTS": "--fuzz=0"}, timeout=45)
    if q.returncode != 0 or "offset " in q.stdout or "fuzz " in q.stdout:
        sys.exit("Quilt refused patch: " + name + "\n" + q.stdout)
version = "2.4.29-1ubuntu4.27+unibo0~experimental1"
date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
entry = ("apache2 ("+version+") bionic; urgency=medium\n\n"
         "  * Experimental, limited security backport (not ESM-equivalent).\n"
         "  * Import CVE-2026-63292 and CVE-2026-56153 from Jammy source.\n\n"
         " -- LegacyPackages CI <noreply@github.com>  "+date+"\n\n")
changelog = src / "debian/changelog"
changelog.write_text(entry + changelog.read_text(encoding="utf-8"), encoding="utf-8")
(out / "EXPERIMENTAL-MANIFEST.md").write_text(
    "# Bionic experimental Apache package\n\n"
    "Source: Ubuntu 18.04 apache2 2.4.29-1ubuntu4.27.\n\n"
    "Package: `"+version+"`.\n\n"
    "Selected, exact zero-fuzz/zero-offset Jammy patches:\n\n"
    + "".join("- `"+p+"`\n" for p in candidates)
    + "\nNo claim of full Bionic ESM equivalence or exhaustive CVE remediation.\n"
)
print("Prepared:",version, "patches:", candidates)
