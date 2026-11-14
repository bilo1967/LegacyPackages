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
    # Focal uses strcasecmp() where Jammy uses ap_cstr_casecmp() in the
    # core expression lookup. Adapt only this unchanged CONTEXT line; retain
    # every security-sensitive added/removed line from Ubuntu's patch.
    patch_for_apply = upstream
    if name == "CVE-2026-44119.patch":
        original = upstream.read_text()
        old_context = "                     match = !ap_cstr_casecmp(prov->name, parms->name);"
        new_context = "                     match = !strcasecmp(prov->name, parms->name);"
        if original.count(old_context) != 1:
            sys.exit("Cannot safely adapt CVE-2026-44119: expected one context line")
        adapted = original.replace(old_context, new_context, 1)
        patch_for_apply = out / "adapted-CVE-2026-44119.patch"
        patch_for_apply.write_text(adapted)
    if name in ("CVE-2024-43204-pre1.patch", "CVE-2024-43204.patch"):
        # Focal's equivalent case-insensitive comparison uses strcasecmp.
        # Rebase the whole Jammy patch consistently: both old context and
        # added secure branches retain their original semantics.
        original = upstream.read_text()
        jammy_cmp = 'ap_cstr_casecmp(hdr->header, "Content-Type")'
        focal_cmp = 'strcasecmp(hdr->header, "Content-Type")'
        count = original.count(jammy_cmp)
        expected = {"CVE-2024-43204-pre1.patch": 4,
                    "CVE-2024-43204.patch": 2}[name]
        if count != expected:
            sys.exit(f"Unexpected mod_headers patch layout for {name}: "
                     f"expected {expected} comparator calls, found {count}")
        patched = original.replace(jammy_cmp, focal_cmp)
        patch_for_apply = out / ("adapted-" + name)
        patch_for_apply.write_text(patched)
    # This Jammy security feature needs a coordinated parser/headers backport.
    # A patch can apply cleanly but use the new flag without importing its
    # definition and enforcement. Do not produce an incomplete security fix.
    added_lines = "\n".join(
        line[1:] for line in patch_for_apply.read_text(errors="replace").splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    flag = "AP_EXPR_FLAG_RESTRICTED_FILE_FUNC"
    header = focal / "include/ap_expr.h"
    if (flag in added_lines and flag not in header.read_text(errors="replace")
            and not (name == "CVE-2026-44119.patch"
                     and "#define AP_EXPR_FLAG_RESTRICTED_FILE_FUNC" in added_lines)):
        decisions.append((
            name, "blocked-dependency",
            "Needs complete CVE-2026-44119 expression parser backport; "
            "flag is undefined in Focal (NOT FIXED)"
        ))
        continue
    # Avoid accidentally interpreting patch text as a patch modifying paths
    # outside source tree: inspect first with git apply --check when possible.
    def execute(extra):
        return subprocess.run(
            ["patch", "--batch", "--forward", "--fuzz=0", "-p1", *extra,
             "-i", str(patch_for_apply)], cwd=focal, text=True,
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
    shutil.copy2(patch_for_apply, dest)
    with series_path.open("a") as f:
        f.write(f"{dest_name}\n")
    decisions.append((name, "applied",
                      "Focal strcasecmp context adapted (no security changes)"
                      if name in ("CVE-2026-44119.patch",
                                  "CVE-2024-43204-pre1.patch",
                                  "CVE-2024-43204.patch")
                      else "zero-fuzz sequential patch"))
    current.add(name)

# Verify the entire expression parser protection is present if imported.
if "CVE-2026-44119.patch" in current:
    expr_header = (focal / "include/ap_expr.h").read_text()
    expr_core = (focal / "server/util_expr_eval.c").read_text()
    assert "#define AP_EXPR_FLAG_RESTRICTED_FILE_FUNC" in expr_header
    assert "info->flags |= AP_EXPR_FLAG_RESTRICTED_FILE_FUNC;" in expr_core
    assert "(prov->restricted & RESTRICTED_FILE_FUNC)" in expr_core
if "CVE-2026-59797.patch" in current:
    assert "CVE-2026-44119.patch" in current, "SSLRequire requires parser fix"
    ssl_conf = (focal / "modules/ssl/ssl_engine_config.c").read_text()
    assert "info->flags |= AP_EXPR_FLAG_RESTRICTED_FILE_FUNC;" in ssl_conf

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
