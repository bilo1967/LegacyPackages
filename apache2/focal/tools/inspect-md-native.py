#!/usr/bin/env python3
"""Inspect actual Focal mod_md renewal/backoff implementation for native CVE port."""
import pathlib
import re
import sys

if len(sys.argv) != 4:
    sys.exit("usage: inspect-md-native.py FOCAL_SOURCE JAMMY_SOURCE OUTPUT")
focal, jammy, output = (pathlib.Path(s).resolve() for s in sys.argv[1:])
paths = {
    "Focal": focal / "modules/md",
    "Jammy": jammy / "modules/md",
}
# Highlight the CVE's actual affected logic, not a blind 28-file transplant.
patterns = re.compile(
    r"backoff|retry|next_run|renewal|failover|exponent|overflow|"
    r"APR_TIME_MAX|apr_time_from_sec|apr_time_sec|md_job", re.I
)
lines = [
    "# Native Focal mod_md security-porting worklist",
    "",
    "Diagnostic only. Neither a successful build nor this report fixes a CVE.",
    "Focus: CVE-2025-55753, ACME renewal retry-timer overflow.",
    "",
]
for label, root in paths.items():
    lines += [f"## {label} matching renewal and retry logic", ""]
    total = 0
    for p in sorted(root.glob("*.[ch]")):
        source = p.read_text(errors="replace").splitlines()
        hits = [i for i, line in enumerate(source)
                if patterns.search(line) and not line.lstrip().startswith("*")]
        if not hits:
            continue
        # Group nearby matches and show concise source context.
        ranges = []
        for i in hits:
            start, end = max(0, i - 3), min(len(source), i + 4)
            if ranges and start <= ranges[-1][1]:
                ranges[-1] = (ranges[-1][0], max(end, ranges[-1][1]))
            else:
                ranges.append((start, end))
        lines += [f"### {p.name}: {len(hits)} matches", ""]
        for start, end in ranges[:12]:
            lines += ["~~~c"]
            lines += [f"{i + 1:5}: {source[i]}" for i in range(start, min(end, start + 36))]
            lines += ["~~~", ""]
        total += len(hits)
    lines += [f"Total matching source lines: {total}", ""]
for name in ("CVE-2025-55753.patch", "CVE-2025-55753-3.patch",
             "CVE-2026-29168.patch"):
    patch = jammy / "debian/patches" / name
    if not patch.exists():
        sys.exit(f"Missing upstream patch: {patch}")
    lines += [f"## {name}: affected hunks", "", "~~~text"]
    for line in patch.read_text(errors="replace").splitlines():
        if line.startswith(("+++ b/", "@@ ")):
            lines.append(line)
    lines += ["~~~", ""]
# Capture the COMPLETE short follow-up patch, plus exact native merge function.
followup = jammy / "debian/patches/CVE-2025-55753-3.patch"
lines += ["## Complete CVE-2025-55753-3 follow-up", "", "~~~diff",
          *followup.read_text(errors="replace").splitlines(), "~~~", ""]
native_cfg = (focal / "modules/md/mod_md_config.c").read_text().splitlines()
matches = [i for i, line in enumerate(native_cfg)
           if "md_config_merge(" in line]
if not matches:
    sys.exit("Focal md_config_merge missing")
for i in matches:
    lines += ["## Native Focal md_config_merge", "", "~~~c"]
    lines += [f"{j+1:5}: {native_cfg[j]}" for j in range(max(0, i-8),
              min(len(native_cfg), i+105))]
    lines += ["~~~", ""]

lines += [
    "## Decision gates",
    "",
    "- Preserve Focal's Apache module ABI; no core API shims in release packages.",
    "- Port bounded retry/backoff math at the matching native Focal call sites.",
    "- Check whether Focal has the affected OCSP HTTP response path before",
    "  considering CVE-2026-29168 not applicable.",
    "- Reuse the existing experimental Focal build and PHP/HTTP test matrix.",
    "",
]
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text("\n".join(lines))
print(f"Native mod_md review written: {output}")
