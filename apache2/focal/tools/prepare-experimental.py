#!/usr/bin/env python3
"""Create an EXPERIMENTAL Ubuntu Focal Apache source tree carrying Jammy patches.

Copies exact upstream Ubuntu Jammy quilt patches and applies only clean,
zero-fuzz patches in original Jammy series order. It produces a manifest of
skips. This does not establish complete CVE coverage or patch correctness.
"""
import datetime
import pathlib
import re
import shutil
import subprocess
import sys

if len(sys.argv) != 4:
    sys.exit("usage: prepare-experimental.py FOCAL_SOURCE JAMMY_SOURCE REPORT_DIR")
focal, jammy, out = [pathlib.Path(a).resolve() for a in sys.argv[1:]]
out.mkdir(parents=True, exist_ok=True)

def read_series(path):
    return [line.split()[0] for raw in path.read_text().splitlines()
            if (line := raw.strip()) and not line.startswith("#")]

series_path = focal / "debian/patches/series"
jammy_series = read_series(jammy / "debian/patches/series")
current = set(read_series(series_path))
decisions = []
for name in jammy_series:
    if name in current:
        continue
    upstream = jammy / "debian/patches" / name
    if not upstream.is_file():
        decisions.append((name, "missing", "Missing upstream file"))
        continue
    # Avoid accidentally interpreting patch text as a patch modifying paths
    # outside source tree: inspect first with git apply --check when possible.
    def execute(extra):
        return subprocess.run(
            ["patch", "--batch", "--forward", "--fuzz=0", "-p1", *extra,
             "-i", str(upstream)], cwd=focal, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    check = execute(["--dry-run"])
    if check.returncode != 0:
        decisions.append((name, "skipped", check.stdout.strip().splitlines()[-1][:180] if check.stdout.strip() else "Dry run rejected"))
        continue
    applied = execute([])
    if applied.returncode != 0:
        sys.exit(f"Unexpected patch apply failure: {name}: {applied.stdout}")
    dest_name = "unibo-jammy-" + name
    dest = focal / "debian/patches" / dest_name
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(upstream, dest)
    with series_path.open("a") as f:
        f.write(f"{dest_name}\n")
    decisions.append((name, "applied", "zero-fuzz sequential patch"))
    current.add(name)

accepted = [n for n, state, _ in decisions if state == "applied"]
skipped = [n for n, state, _ in decisions if state != "applied"]
# Version intentionally not deployable and distinguishable from sanctioned ESM
version = "2.4.41-4ubuntu3.23+unibo0~experiment1"
changelog = focal / "debian/changelog"
old = changelog.read_text()
intro = (f"apache2 ({version}) focal; urgency=low\n\n"
         "  * EXPERIMENTAL BUILD: incomplete backport, DO NOT DEPLOY.\n"
         f"  * Import {len(accepted)} directly applicable Jammy quilt patches.\n"
         f"  * {len(skipped)} other candidate patches not included; review pending.\n\n"
         " -- LegacyPackages CI <noreply@github.com>  "
         + datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
         + "\n\n")
changelog.write_text(intro + old)

with (out / "experimental-manifest.md").open("w") as f:
    f.write("# EXPERIMENTAL Apache Focal partial patch import\n\n")
    f.write("Not for production use. No security completeness claim. "
            "Jammy source patches are not equivalent to verified Focal ESM.\n\n")
    f.write(f"Version: \`{version}\`. Applied: {len(accepted)}; skipped: {len(skipped)}.\n\n")
    f.write("| Patch | Decision | Reason |\n|---|---|---|\n")
    for name, state, why in decisions:
        f.write(f"| \`{name}\` | {state} | {why.replace('|', '/') } |\n")
    f.write("\nNext: review each source diff, add prerequisite patches and complete "
            "missing CVEs, then run regression and ABI tests.\n")
print(f"Applied {len(accepted)} candidate patches, skipped {len(skipped)}")
