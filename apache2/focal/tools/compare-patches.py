#!/usr/bin/env python3
"""List possible *names* missing from Focal's quilt series.

Discovery only. No copied patch is presumed to apply to Focal.
"""
import pathlib
import re
import shutil
import sys

if len(sys.argv) != 4:
    raise SystemExit("usage: compare-patches.py FOCAL_SOURCE JAMMY_SOURCE OUTPUT")
focal, jammy, out = map(pathlib.Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=True)

def series(source):
    path = source / "debian/patches/series"
    return [
        ln.strip().split()[0]
        for ln in path.read_text().splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]

old = series(focal)
new = series(jammy)
old_names = set(old)
candidates = [name for name in new if name not in old_names]
cve_pat = re.compile(r"CVE-\d{4}-\d{4,}")
old_cves = set().union(*(set(cve_pat.findall(n)) for n in old))
new_cves = set().union(*(set(cve_pat.findall(n)) for n in new))
target = out / "jammy-only-patches"
target.mkdir(exist_ok=True)
with (out / "report.md").open("w") as f:
    f.write("# Ubuntu Apache patch series comparison\n\n")
    f.write("Focal: Apache 2.4.41; Jammy: Apache 2.4.52.\n\n")
    f.write("**Discovery only**: Jammy patch names are not a complete ESM patch list; different patch names do not establish missing CVE fixes. Do not install the resulting artifacts.\n\n")
    f.write(f"Focal series entries: {len(old)}; Jammy: {len(new)}; names only in Jammy: {len(candidates)}.\n\n")
    f.write("## CVE identifiers mentioned in Jammy filenames, but not Focal filenames\n\n")
    for cve in sorted(new_cves - old_cves):
        f.write(f"- {cve}\n")
    f.write("\n## Jammy-only patch filenames\n\n")
    for name in candidates:
        source = jammy / "debian/patches" / name
        if source.is_file():
            dest = target / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, dest)
            f.write(f"- `{name}`\n")
        else:
            f.write(f"- MISSING FILE: `{name}`\n")
print((out / "report.md").read_text()[:3000])
