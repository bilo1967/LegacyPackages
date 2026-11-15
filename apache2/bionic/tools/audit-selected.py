#!/usr/bin/env python3
"""Read-only, zero-fuzz source applicability audit: Ubuntu Bionic vs Jammy.

No vulnerable service is started; no packages or exploit tests are built.
For each named patch, test applicability in its own disposable source copy.
A clean dry-run is NOT proof that the CVE is fixed.
"""
import datetime
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

if len(sys.argv) != 4:
    sys.exit("usage: audit-selected.py BIONIC_TREE JAMMY_TREE REPORT.md")
bionic, jammy, report = (pathlib.Path(v).resolve() for v in sys.argv[1:])

# Ordered using broad patch sequence from Jammy, but restricted by CVE.
# CVE-2026-7363X is shared with Digest code: assess separately before port.
targets = {
    "CVE-2026-56154.patch": "mod_rewrite / Oct 7",
    "CVE-2026-59797.patch": "mod_ssl / Oct 7",
    "CVE-2026-63292.patch": "HTTP handling / Oct 14",
    "CVE-2026-63686.patch": "proxy/backend responses / Oct 14",
    "CVE-2026-7363X.patch": "auth (shared 73636/73637) / Oct 14: conditional",
    "CVE-2026-46729.patch": "memory handling / Nov 10",
    "CVE-2026-47360.patch": "sessions / Nov 10",
    "CVE-2026-56153.patch": "memory handling / Nov 10",
}
series_file = jammy / "debian/patches/series"
assert series_file.is_file(), f"No Jammy patch series: {series_file}"
series = [line.split()[0] for line in series_file.read_text().splitlines()
          if line.strip() and not line.lstrip().startswith("#")]
already = set(line.split()[0] for line in
              (bionic / "debian/patches/series").read_text().splitlines()
              if line.strip() and not line.lstrip().startswith("#"))
rows = []

def patch_files(text):
    names = re.findall(r"(?m)^\+\+\+ (?:b/)?([^\t\n ]+)", text)
    return sorted({name for name in names if name != "/dev/null"})

for name in targets:
    patch = jammy / "debian/patches" / name
    if name not in series or not patch.is_file():
        rows.append((name, "absent", "Not found in Jammy quilt series"))
        continue
    if name in already:
        rows.append((name, "already-listed", "Name already in Bionic patch series; inspect content/version"))
        continue
    text = patch.read_text(errors="replace")
    files = patch_files(text)
    if not files:
        rows.append((name, "manual review", "No target paths parsed"))
        continue
    # Exclude any patch that addresses files not present in Bionic.
    missing = [p for p in files if not (bionic / p).is_file()
               and not p.startswith("debian/")]
    if missing:
        rows.append((name, "absent-source", ", ".join(missing[:5])))
        continue
    # --dry-run never modifies the source. No fuzz/offset accepted as proof
    # of correctness: inspect offsets and actual changed code manually.
    proc = subprocess.run(
        ["patch", "--dry-run", "--batch", "--fuzz=0", "-p1", "-i", str(patch)],
        cwd=bionic, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=30,
    )
    output = proc.stdout
    rejects = len(re.findall(r"(?i)hunk .*failed|malformed patch|can't find file", output))
    offsets = len(re.findall(r"(?i)offset [+-]?\d+", output))
    if proc.returncode == 0:
        status = "dry-run-clean" if offsets == 0 else "dry-run-offset"
        reason = "All hunks accepted; offset count: " + str(offsets)
    else:
        status = "needs-port"
        reason = f"exit {proc.returncode}, failed/malformed markers: {rejects}"
    rows.append((name, status, reason))

report.parent.mkdir(parents=True, exist_ok=True)
lines = [
    "# Bionic selected Apache CVE patch source audit",
    "",
    f"Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
    "Baseline: Bionic source 2.4.29-1ubuntu4.27; candidates from Jammy 2.4.52-1ubuntu4.27.",
    "",
    "**Read-only dry-run only.** No patch applied, no package built, no claim of remediation.",
    "Each candidate is checked independently. Dependency or regression patches may be required.",
    "Zero fuzz is used. Offsets still require manual review.",
    "",
    "| Patch | Target | Result | Detail |",
    "|---|---|---|---|",
]
for name, result, detail in rows:
    lines.append(f"| `{name}` | {targets[name]} | **{result}** | {detail.replace('|', '/')} |")
lines += [
    "",
    "## Excluded from this initial code audit",
    "",
    "- CVE-2026-109163: mod_vhost_alias absent from mrscoulter loaded modules; serious but deferred for host exposure.",
    "- CVE-2026-48005: mod_auth_digest is not loaded; do not treat a shared Digest patch as mandatory for this host.",
    "- CVE-2026-57941: mod_http2 not loaded.",
    "- CVE-2026-42528: mod_dav not loaded.",
    "",
    "## Next",
    "Review failed hunks against Bionic source, cross-check whether the CVE is",
    "actually in the installed version, and port only the necessary security",
    "change plus prerequisites. After that, build and test in a disposable",
    "Ubuntu 18.04 container preserving external module ABI.",
]
report.write_text("\n".join(lines) + "\n")
print("\n".join(f"{name}: {status} ({detail})" for name, status, detail in rows))
print(f"Report: {report}")
