#!/usr/bin/env python3
"""Audit Focal mod_md/OCSP feature gaps without importing partial CVE patches.

This is an architecture and exposure diagnostic, NOT a security fix.
"""
import pathlib
import re
import sys

if len(sys.argv) != 4:
    sys.exit("usage: audit-mod-md.py FOCAL_SOURCE JAMMY_SOURCE REPORT_PATH")
focal, jammy, report = [pathlib.Path(s).resolve() for s in sys.argv[1:]]
rel = pathlib.Path("modules/md")
focal_md, jammy_md = focal / rel, jammy / rel
missing_ocsp = ("md_ocsp.c", "md_ocsp.h", "mod_md_ocsp.c", "mod_md_ocsp.h")
for name in missing_ocsp:
    if not (jammy_md / name).is_file():
        sys.exit("Jammy mod_md OCSP prerequisite missing: " + name)
if any((focal_md / name).exists() for name in missing_ocsp):
    sys.exit("Focal OCSP architecture changed: reassess module exposure")

version_expr = re.compile(r'(?m)^#define MOD_MD_VERSION "([^"]+)"')
def version(root):
    match = version_expr.search((root / rel / "md_version.h").read_text())
    if not match:
        sys.exit("mod_md version not found")
    return match.group(1)

focal_version, jammy_version = version(focal), version(jammy)
# Never claim the CVEs fixed merely because newer OCSP source files are absent.
series = (focal / "debian/patches/series").read_text()
excluded = (
    "CVE-2025-55753.patch",
    "CVE-2025-55753-3.patch",
    "CVE-2026-29168.patch",
)
if any(re.search(r"(?m)^" + re.escape(name) + r"\s*$", series)
       for name in excluded):
    sys.exit("mod_md group unexpectedly marked applied: manual review required")
text = [
    "# Apache Focal experimental mod_md architecture audit",
    "",
    "Diagnostic only. No production suitability or CVE remediation claim.",
    "",
    f"- Focal mod_md module version: \`{focal_version}\`.",
    f"- Jammy mod_md module version: \`{jammy_version}\`.",
    "- Focal lacks the OCSP source implementation present in Jammy:",
]
text.extend(f"  - \`modules/md/{name}\`" for name in missing_ocsp)
text += [
    "",
    "## CVE disposition",
    "",
    "- \`CVE-2025-55753.patch\`: **not imported**. Broad API and ACME/OCSP "
    "changes require an integrated source-level port and runtime review.",
    "- \`CVE-2025-55753-3.patch\`: **not imported**. Depends on "
    "newer mod_md configuration and \`mod_md_ocsp.c\`.",
    "- \`CVE-2026-29168.patch\`: **not imported**. Targets the newer "
    "\`md_ocsp.c\` OCSP HTTP request engine absent in Focal.",
    "",
    "Missing source files do not prove the deployed module is safe: "
    "other ACME, certificate renewal, OCSP, and HTTP paths still need "
    "separate threat and regression review.",
    "",
    "A basic mod_md load smoke test is not an ACME or OCSP security test.",
    "",
]
report.parent.mkdir(parents=True, exist_ok=True)
report.write_text("\n".join(text))
print(f"mod_md architecture: Focal {focal_version}, Jammy {jammy_version}; "
      "three patches deliberately excluded; report generated")
