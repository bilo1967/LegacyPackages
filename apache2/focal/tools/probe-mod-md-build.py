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
# Work on an isolated copy; NEVER alter the official downloaded source.
# The version guard is bypassed solely to expose subsequent compiler errors.
# The resulting object MUST NOT be loaded or installed, even if it links.
source_md = md
md = out / "mod-md-source-diagnostic"
if md.exists():
    shutil.rmtree(md)
shutil.copytree(source_md, md)
source_file = md / "mod_md.c"
guard = '#error "This version of mod_md requires Apache httpd 2.4.48 or newer."'
source = source_file.read_text()
if source.count(guard) != 1:
    sys.exit("Unexpected mod_md version guard: diagnostic must be reviewed")
source_file.write_text(source.replace(guard,
    '#warning "DIAGNOSTIC ONLY: unsupported Focal Apache API; never deploy this module"'))
files = [md / (name + ".c") for name in names]
apxs = shutil.which("apxs") or shutil.which("apxs2")
if not apxs:
    sys.exit("Focal apache2-dev missing apxs")
# Stage-2 diagnostic: isolate only the unavailable Jammy SSL API header.
# This does NOT make that API available in Focal's runtime or guarantee ABI safety.
# In particular, never add the whole Jammy include/ directory to the search path.
ssl_header = root / "include" / "http_ssl.h"
if not ssl_header.is_file():
    sys.exit("Expected Jammy include/http_ssl.h missing")
header_dir = out / "jammy-header-only"
header_dir.mkdir(exist_ok=True)
shutil.copy2(ssl_header, header_dir / "http_ssl.h")
args = [apxs, "-c", "-I" + str(md), "-I" + str(header_dir),
        "-lssl", "-lcrypto", "-lcurl", "-ljansson"] + [str(f) for f in files]
try:
    r = subprocess.run(args, cwd=md, capture_output=True, text=True,
                       errors="replace", timeout=480)
    output = r.stdout + "\n--- stderr ---\n" + r.stderr
    code = r.returncode
    status = "COMPILED_UNSUPPORTED" if code == 0 else "INCOMPATIBLE"
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
    "- Stage-3 diagnostic: Jammy http_ssl.h supplied from isolated include path.",
    "- Minimum Apache 2.4.48 guard bypassed ONLY in disposable source copy.",
    "- WARNING: any resulting module is unsupported and must NOT be loaded or deployed.",
    "- ABI note: declarations do not provide missing Focal core/mod_ssl hooks or symbols.",
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
if status != "COMPILED_UNSUPPORTED":
    print("Compiler output (first relevant diagnostics):")
    print("\n".join(issues[:25]) if issues else output[-3000:])
    sys.exit(1)
module = md / ".libs" / "mod_md.so"
if not module.is_file():
    print("apxs returned success but did not produce .libs/mod_md.so")
    (out / "report.md").write_text(
        (out / "report.md").read_text()
        + "\n**Missing shared object after successful compiler exit.**\n"
    )
    sys.exit(1)
print("Built unsupported diagnostic module:", module)
print("NOT loading module: Apache 2.4.48 version guard bypassed; ABI unverified")
sys.exit(1)
