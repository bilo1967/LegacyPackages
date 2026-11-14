#!/usr/bin/env python3
"""Inspect rejected Apache expression security patches after partial import."""
import pathlib
import re
import subprocess
import sys
if len(sys.argv) != 4:
    sys.exit("usage: inspect-44119.py FOCAL_SOURCE JAMMY_SOURCE OUT")
focal, jammy, out = (pathlib.Path(p).resolve() for p in sys.argv[1:])
out.mkdir(parents=True, exist_ok=True)
with (out / "expression-parser-diagnostics.txt").open("w") as f:
    for name in ["CVE-2026-44119.patch", "CVE-2026-59797.patch"]:
        path = jammy / "debian/patches" / name
        f.write("\n" + "=" * 20 + name + "=" * 20 + "\n")
        r = subprocess.run(["patch", "--batch", "--forward", "--fuzz=0",
                            "--dry-run", "-p1", "-i", str(path)],
                           cwd=focal, text=True, capture_output=True)
        f.write("Dry-run exit code: " + str(r.returncode) + "\n" + r.stdout + r.stderr)
        data = path.read_text()
        for chunk in re.split(r"(?=^--- a/)", data, flags=re.MULTILINE):
            m = re.search(r"^\+\+\+ b/(\S+)", chunk, re.MULTILINE)
            if not m:
                continue
            rel = m.group(1)
            if not rel.startswith(("include/", "server/", "modules/")):
                continue
            f.write("\n=== PATCH FILE: " + rel + " ===\n" + chunk[:15000])
            source = focal / rel
            if not source.is_file():
                f.write("\nMISSING SOURCE FILE\n")
                continue
            lines = source.read_text(errors="replace").splitlines()
            for line in re.findall(r"^@@ -(\d+)", chunk, flags=re.MULTILINE)[:12]:
                a = max(0, int(line)-16)
                b = min(len(lines), a+70)
                f.write("\nCURRENT FOCAL SOURCE LINES " + str(a+1) + "-" + str(b) + "\n")
                f.write("\n".join(str(i+1) + " " + lines[i] for i in range(a,b)) + "\n")
