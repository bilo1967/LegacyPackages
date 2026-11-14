#!/usr/bin/env python3
"""Diagnose skipped Jammy patches against the partially patched Focal tree."""
import pathlib
import re
import subprocess
import sys

if len(sys.argv) != 4:
    sys.exit("usage: inspect-skipped.py FOCAL_TREE JAMMY_TREE OUT_DIR")
focal, jammy, out = [pathlib.Path(x).resolve() for x in sys.argv[1:]]
out.mkdir(parents=True, exist_ok=True)
manifest = (out / "experimental-manifest.md").read_text()
skipped = []
for line in manifest.splitlines():
    parts = [p.strip() for p in line.split("|")]
    if len(parts) >= 4 and parts[2] in ("skipped", "blocked-dependency", "missing"):
        skipped.append((parts[1].strip().strip(chr(96)).strip(chr(92)), parts[2]))
if not skipped:
    sys.exit("No skipped candidates found in manifest")

def try_patch(path, fuzz):
    return subprocess.run(
        ["patch", "--batch", "--forward", "--dry-run", "--fuzz=" + str(fuzz),
         "-p1", "-i", str(path)],
        cwd=focal, text=True, capture_output=True, timeout=60)

report = out / "skipped-patch-diagnostics.md"
with report.open("w") as f:
    f.write("# Remaining Jammy patch candidates: contextual diagnosis\n\n")
    f.write("Informational only. No skipped patch is considered fixed. "
            "Fuzz=1/2 is diagnostic only and does not authorize patching.\n\n")
    for name, status in skipped:
        patch = jammy / "debian/patches" / name
        f.write("## " + name + "\n\n")
        f.write("Previous result: " + status + "\n\n")
        if not patch.is_file():
            f.write("Missing Jammy patch source.\n\n")
            continue
        patch_text = patch.read_text(errors="replace")
        paths = re.findall(r"^\+\+\+ b/([^\n]+)", patch_text, flags=re.MULTILINE)
        f.write("Touched paths: " + ", ".join(paths) + "\n\n")
        for level in (0, 1, 2):
            p = try_patch(patch, level)
            f.write("### Dry run fuzz=" + str(level) + " exit=" + str(p.returncode) + "\n\n")
            f.write("~~~text\n" + (p.stdout + p.stderr)[-3800:] + "\n~~~\n\n")
        for segment in re.split(r"(?=^--- a/)", patch_text, flags=re.MULTILINE):
            m = re.search(r"^\+\+\+ b/(\S+)", segment, flags=re.MULTILINE)
            if not m:
                continue
            rel = m.group(1)
            if not rel.startswith(("include/", "modules/", "server/")):
                continue
            file = focal / rel
            f.write("### " + rel + "\n\n")
            f.write("~~~diff\n" + segment[:4500] + "\n~~~\n\n")
            if not file.is_file():
                f.write("Source file missing in Focal.\n\n")
                continue
            lines = file.read_text(errors="replace").splitlines()
            positions = [int(x) for x in re.findall(r"^@@ -(\d+)", segment, flags=re.MULTILINE)][:3]
            f.write("Relevant Focal source excerpts:\n\n~~~c\n")
            for pos in positions:
                a = max(0, min(pos - 9, len(lines)))
                b = min(len(lines), a + 32)
                f.write("\nFocal lines " + str(a+1) + ".." + str(b) + "\n")
                f.write("\n".join(str(i+1) + " " + lines[i] for i in range(a, b)) + "\n")
            f.write("~~~\n\n")
print("wrote", report, "for", len(skipped), "patches")
