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
args = [apxs, "-c", "-o", "mod_md.so", "-I" + str(md), "-I" + str(header_dir),
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
    "- DSO output explicitly selected via apxs -o mod_md.so.",
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
    print("DSO candidates:", [str(p) for p in md.rglob("*.so")])
    (out / "report.md").write_text(
        (out / "report.md").read_text()
        + "\n**Missing shared object after successful compiler exit.**\n"
    )
    sys.exit(1)
print("Built unsupported diagnostic module:", module)
nm = shutil.which("nm")
if nm:
    symbols = subprocess.run([nm, "-D", "--undefined-only", str(module)],
                             capture_output=True, text=True, errors="replace")
    (out / "undefined-symbols.txt").write_text(symbols.stdout + symbols.stderr)
    with (out / "report.md").open("a") as report_file:
        report_file.write("\n## Undefined dynamic symbols (first 100)\n\n~~~text\n")
        report_file.write("\n".join(symbols.stdout.splitlines()[:100]))
        report_file.write("\n~~~\n\nUnresolved Apache symbols require separate Focal API review.\n")
# Compare dynamic requirements against the actual Focal executable, the linked
# libraries, and *separately* the installed modules. A symbol exported by an
# installed but disabled module is NOT a runtime ABI guarantee.
def dyn_symbols(binary, undefined=False):
    command = [nm, "-D", "--undefined-only" if undefined else "--defined-only",
               str(binary)]
    result = subprocess.run(command, capture_output=True, text=True,
                            errors="replace")
    if result.returncode:
        return set()
    found = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            name = parts[-1].split("@", 1)[0]
            if name:
                found.add(name)
    return found

if nm:
    needed = dyn_symbols(module, undefined=True)
    core_binary = pathlib.Path("/usr/sbin/apache2")
    core = dyn_symbols(core_binary) if core_binary.is_file() else set()
    # ldd is limited to our locally built, disposable diagnostic module.
    ld = subprocess.run(["ldd", str(module)], capture_output=True,
                        text=True, errors="replace")
    (out / "ldd.txt").write_text(ld.stdout + ld.stderr)
    library_paths = set(re.findall(r"/[^\s()]+\.so(?:\.[0-9.]+)?", ld.stdout))
    library_providers = {}
    for library in sorted(library_paths):
        for symbol in dyn_symbols(library):
            library_providers.setdefault(symbol, library)

    module_providers = {}
    installed = pathlib.Path("/usr/lib/apache2/modules")
    if installed.is_dir():
        for candidate in sorted(installed.glob("*.so")):
            # Old mod_md must not be treated as a provider for its replacement.
            if candidate.name == "mod_md.so":
                continue
            for symbol in dyn_symbols(candidate):
                module_providers.setdefault(symbol, []).append(candidate.name)

    missing = sorted(needed - core - library_providers.keys())
    optional = [(symbol, module_providers[symbol])
                for symbol in missing if symbol in module_providers]
    unprovided = [symbol for symbol in missing
                  if symbol not in module_providers]
    def lines(items):
        return "\n".join(items) if items else "(none)"

    audit = [
        "# mod_md experimental ELF dependency audit",
        "",
        "This module is unsupported: the Apache >= 2.4.48 guard was bypassed.",
        "No loading, installation, or security compatibility claim.",
        "",
        f"- Undefined dynamic symbols: {len(needed)}",
        f"- Found in Focal Apache executable: {len(needed & core)}",
        f"- Found in directly linked libraries: {len((needed - core) & library_providers.keys())}",
        f"- Found only in other installed Apache modules: {len(optional)}",
        f"- Not found in these providers: {len(unprovided)}",
        "",
        "## Exported by other installed modules (may be disabled)",
        "",
        "~~~text",
        lines([f"{name}: {', '.join(providers)}" for name, providers in optional]),
        "~~~",
        "",
        "## Not found in inspected Focal exports",
        "",
        "~~~text",
        lines(unprovided),
        "~~~",
        "",
        "This is a static symbol audit, not a runtime test. Module exports",
        "may depend on load order; indirect library dependencies and dynamic",
        "symbol lookups are not fully assessed.",
        "",
    ]
    (out / "symbol-audit.md").write_text("\n".join(audit))
    with (out / "report.md").open("a") as report_file:
        report_file.write("\n## Static ABI symbol audit\n\n")
        report_file.write(f"- Present only in other installed Apache modules: {len(optional)}\n")
        report_file.write(f"- No provider found in inspected binaries: {len(unprovided)}\n")
        report_file.write("- Details: symbol-audit.md\n")
    print(f"Static ABI audit: {len(unprovided)} missing exports, "
          f"{len(optional)} supplied only by installed Apache modules")
print("NOT loading module: Apache 2.4.48 version guard bypassed; ABI unverified")

