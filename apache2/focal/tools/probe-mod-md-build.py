#!/usr/bin/env python3
"""Diagnostic-only Jammy mod_md compilation against Ubuntu 20.04 Apache headers."""
import pathlib
import re
import shutil
import subprocess
import sys

if len(sys.argv) != 3:
    sys.exit("usage: probe-mod-md-build.py JAMMY_SOURCE OUTPUT_DIR")
root = pathlib.Path(sys.argv[1]).resolve()
out = pathlib.Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=True)
md = root / "modules/md"
cfg = (md / "config2.m4").read_text()
m = re.search(r'(?s)\bmd_objs="dnl\s*(.*?)\n"', cfg)
if not m:
    sys.exit("Jammy mod_md build graph not found")
names = list(dict.fromkeys(re.findall(
    r"\b([A-Za-z_][A-Za-z_0-9]*)\.lo\b", m.group(1)
)))
if len(names) < 20 or "mod_md" not in names:
    sys.exit("Unexpected/incomplete Jammy mod_md object inventory")
files = [md / (name + ".c") for name in names]
if not all(f.is_file() for f in files):
    sys.exit("One or more Jammy mod_md build inputs are missing")
apxs = shutil.which("apxs") or shutil.which("apxs2")
if not apxs:
    sys.exit("Focal apache2-dev missing apxs")
args = [apxs, "-c", "-I" + str(md), "-lssl", "-lcrypto",
        "-lcurl", "-ljansson"] + [str(f) for f in files]
try:
    r = subprocess.run(args, cwd=md, capture_output=True, text=True,
                       errors="replace", timeout=480)
    output = r.stdout + "\n--- stderr ---\n" + r.stderr
    code = r.returncode
    status = "COMPILED" if code == 0 else "INCOMPATIBLE"
except subprocess.TimeoutExpired as exc:
    def decode(value):
        return (value or b"").decode("utf-8", "replace") if isinstance(value, bytes) else (value or "")
    output = decode(exc.stdout) + "\n--- stderr ---\n" + decode(exc.stderr)
    code, status = 124, "TIMEOUT"
(out / "compiler.log").write_text(output)
issues = [line for line in output.splitlines()
          if re.search(r"(?i)error:|warning:|undefined reference|cannot find|no such file", line)]
report = [
    "# Jammy mod_md compatibility with Focal development headers",
    "",
    "Diagnostic only; no module installation or CVE remediation.",
    "",
    "- Environment: disposable Ubuntu 20.04 container, stock apache2-dev.",
    "- Source: Ubuntu Jammy patched Apache 2.4.52-1ubuntu4.27.",
    f"- Module object count: {len(files)} (complete Jammy config2.m4 md_objs).",
    f"- Compile status: **{status}** (exit code {code}).",
    "- Full log: compiler.log.",
    "",
    "## First compiler diagnostics",
    "",
    "~~~text",
] + (issues[:100] or ["No diagnostic matches; see full log."]) + [
    "~~~", "",
    "A compile success does not establish runtime/API compatibility with",
    "the patched Focal Apache, ACME issuance, renewal, or OCSP behavior.",
]
(out / "report.md").write_text("\n".join(report) + "\n")
print(f"mod_md full-source Focal header probe: {status} ({code}), {len(files)} source files")
# A compiler failure is diagnostic data. Infrastructure failures above remain fatal.
