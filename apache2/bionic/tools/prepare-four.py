#!/usr/bin/env python3
"""Build four-CVE Bionic source by preserving Ubuntu quilt and ABI.

Uses two exact vendor patches plus native, guarded ports of the original
mod_rewrite and mod_ssl additions. Not a claim of ESM equivalence.
Python 3.6 compatible (Ubuntu 18.04).
"""
from datetime import datetime, timezone
from pathlib import Path
import difflib
import os
import shutil
import subprocess
import sys

if len(sys.argv) != 4:
    sys.exit("usage: prepare-four.py BIONIC_SOURCE JAMMY_PATCH_ROOT OUTPUT_REPORT")
src, vendor, out = [Path(x).resolve() for x in sys.argv[1:]]
out.mkdir(parents=True, exist_ok=True)
version = "2.4.29-1ubuntu4.27+unibo0~experimental2"
patch_dir = src / "debian/patches"
series = patch_dir / "series"
existing = set(l.split()[0] for l in series.read_text().splitlines()
               if l.strip() and not l.startswith("#"))
source_names = ["CVE-2026-63292.patch", "CVE-2026-56153.patch"]
port_names = ["unibo-CVE-2026-56154-bionic.patch",
              "unibo-CVE-2026-59797-bionic.patch"]
for name in source_names + port_names:
    if name in existing:
        sys.exit("Already present in Bionic patch series: " + name)

def run_quilt(name):
    p=subprocess.run(["quilt", "push", "-a"], cwd=src, universal_newlines=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=dict(os.environ, QUILT_PATCHES="debian/patches",
                 QUILT_PATCH_OPTS="--fuzz=0"), timeout=60)
    if p.returncode or "offset " in p.stdout or "fuzz " in p.stdout:
        sys.exit("Quilt rejected " + name + "\n" + p.stdout)

def add(name, content):
    (patch_dir/name).write_text(content, encoding="utf-8")
    with series.open("a", encoding="utf-8") as f:
        f.write(name + "\n")
    run_quilt(name)

def native_diff(path, old, new, label):
    if old == new:
        sys.exit("No source modification generated for " + label)
    diff="".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile="a/"+path, tofile="b/"+path, n=3))
    if not diff: sys.exit("Missing diff for " + label)
    return ("Description: Narrow Bionic port of "+label+
            "; content reviewed against Jammy source.\n"
            "Origin: Ubuntu Jammy apache2 2.4.52-1ubuntu4.27\n"
            "Forwarded: not-needed\n---\n"+diff)

for name in source_names:
    original=vendor/"debian/patches"/name
    if not original.is_file(): sys.exit("Missing Jammy reference patch "+name)
    p=subprocess.run(["patch","--dry-run","--batch","--fuzz=0","-p1","-i",str(original)],
       cwd=src, universal_newlines=True, stdout=subprocess.PIPE,
       stderr=subprocess.STDOUT, timeout=30)
    if p.returncode or "offset " in p.stdout or "fuzz " in p.stdout:
        sys.exit("Source patch no longer clean: "+name+"\n"+p.stdout)
    add(name,original.read_text(encoding="utf-8"))

# Port of CVE-2026-56154: preserve ctx->vary_this outside the lifetime of
# both LA-U and LA-F subrequests. Exactly two independently reviewed sites.
rew=src/"modules/mappers/mod_rewrite.c"
old=rew.read_text(encoding="utf-8")
anchor=("                    ctx->r = r;\n"
        "                    ap_destroy_sub_req(rr);")
addendum=("                    ctx->r = r;\n"
          "                    if (ctx->vary_this) {\n"
          "                        ctx->vary_this = apr_pstrdup(r->pool, ctx->vary_this);\n"
          "                    }\n"
          "                    ap_destroy_sub_req(rr);")
vendor_rew=(vendor/"debian/patches/CVE-2026-56154.patch").read_text(encoding="utf-8")
security_add="+                    if (ctx->vary_this) {"
if old.count(anchor)!=2 or vendor_rew.count(security_add)!=2:
    sys.exit("Unexpected rewrite source or upstream patch shape; refuse port")
add(port_names[0], native_diff("modules/mappers/mod_rewrite.c",old,
                              old.replace(anchor,addendum), "CVE-2026-56154"))

# Port of CVE-2026-59797: the SSLRequire restricted-file-functions flag
# is inserted only if Bionic actually implements the flag in its API.
ssl=src/"modules/ssl/ssl_engine_config.c"
old=ssl.read_text(encoding="utf-8")
anchor=("    info->module_index = APLOG_MODULE_INDEX;\n"
        "    errstring = ap_expr_parse(cmd->pool, cmd->temp_pool, info, arg, NULL);")
addendum=("    info->module_index = APLOG_MODULE_INDEX;\n"
          "    if (cmd->pool == cmd->temp_pool) {\n"
          "        info->flags |= AP_EXPR_FLAG_RESTRICTED_FILE_FUNC;\n"
          "    }\n"
          "    errstring = ap_expr_parse(cmd->pool, cmd->temp_pool, info, arg, NULL);")
vendor_ssl=(vendor/"debian/patches/CVE-2026-59797.patch").read_text(encoding="utf-8")
if old.count(anchor)!=1 or vendor_ssl.count("+        info->flags |= AP_EXPR_FLAG_RESTRICTED_FILE_FUNC;")!=1:
    sys.exit("Unexpected SSLRequire context or vendor patch; refuse port")
flag_support = any("AP_EXPR_FLAG_RESTRICTED_FILE_FUNC" in p.read_text(
    encoding="utf-8",errors="replace") for p in
    list((src/"include").glob("*.h"))+list((src/"server").glob("*.c")))
if not flag_support:
    sys.exit("Bionic lacks AP_EXPR_FLAG_RESTRICTED_FILE_FUNC; require separate expression API port")
add(port_names[1], native_diff("modules/ssl/ssl_engine_config.c",old,
                              old.replace(anchor,addendum), "CVE-2026-59797"))

date=datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
entry=("apache2 ("+version+") bionic; urgency=medium\n\n"
       "  * Experimental selective security backport; not ESM-equivalent.\n"
       "  * Import CVE-2026-63292 and CVE-2026-56153 unchanged.\n"
       "  * Native Bionic ports of CVE-2026-56154 and CVE-2026-59797.\n\n"
       " -- LegacyPackages CI <noreply@github.com>  "+date+"\n\n")
changelog=src/"debian/changelog"
changelog.write_text(entry+changelog.read_text(encoding="utf-8"),encoding="utf-8")
(out/"EXPERIMENTAL-MANIFEST.md").write_text(
    "# Apache Bionic four-CVE experimental backport\n\n"
    "Version: `"+version+"`\n\n"
    "Exact Ubuntu Jammy quilt patches:\n"+
    "".join("- `"+p+"`\n" for p in source_names)+
    "\nNative Bionic source-context ports:\n"+
    "".join("- `"+p+"`\n" for p in port_names)+
    "\nNo claim of full remediation or Ubuntu ESM equivalence.\n",
    encoding="utf-8")
print("Prepared Bionic",version,"with four reviewed CVE patch entries")
