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
              "unibo-CVE-2026-44119-bionic.patch",
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

# Port the dependency CVE-2026-44119 first: Bionic does not yet define
# AP_EXPR_FLAG_RESTRICTED_FILE_FUNC or distinguish expression file tests
# from file-reading functions. Carry the upstream parser restrictions,
# skipping Jammy-only removal hunks absent in Bionic source.
header=src/"include/ap_expr.h"
old_header=header.read_text(encoding="utf-8")
header_anchor="#define AP_EXPR_FLAG_STRING_RESULT         8\\n"
header_more=("#define AP_EXPR_FLAG_STRING_RESULT         8\\n"
             "/** Don't allow functions/vars that expose filesystem contents. */\\n"
             "#define AP_EXPR_FLAG_RESTRICTED_FILE_FUNC   16\\n")
if old_header.count(header_anchor)!=1:
    sys.exit("Unexpected Bionic expression flag definitions")
new_header=old_header.replace(header_anchor,header_more)

expr=src/"server/util_expr_eval.c"
old_expr=expr.read_text(encoding="utf-8")
new_expr=old_expr

def replace_checked(hay,old,new,count=1):
    if hay.count(old)!=count:
        sys.exit("Unexpected expression parser context: "+repr(old[:100])+
                 " (count "+str(hay.count(old))+")")
    return hay.replace(old,new,count)

new_expr=replace_checked(new_expr,
    "    info->module_index = module_index;\\n"
    "    *err = ap_expr_parse(cmd->pool, cmd->temp_pool, info, expr, lookup_fn);",
    "    info->module_index = module_index;\\n"
    "    /* Reject file-content functions in .htaccess expressions. */\\n"
    "    if (cmd->pool == cmd->temp_pool) {\\n"
    "        info->flags |= AP_EXPR_FLAG_RESTRICTED_FILE_FUNC;\\n"
    "    }\\n"
    "    *err = ap_expr_parse(cmd->pool, cmd->temp_pool, info, expr, lookup_fn);")
new_expr=replace_checked(new_expr,
    "struct expr_provider_single {",
    "#define RESTRICTED_FILE_TEST 0x01\\n"
    "#define RESTRICTED_FILE_FUNC 0x02\\n"
    "#define RESTRICTED_ALL (RESTRICTED_FILE_TEST | RESTRICTED_FILE_FUNC)\\n"
    "struct expr_provider_single {")
new_expr=replace_checked(new_expr,
    "    int restricted;\\n};\\n\\nstruct expr_provider_multi",
    "    unsigned int restricted;\\n};\\n\\nstruct expr_provider_multi")
for symbol in ["file_func", "filesize_func"]:
    # Match the relevant provider entry, not other possible source references.
    import re
    match=re.search(r"(?m)^([ \\t]*\\{ "+symbol+r",[^\\n]*?), 1 \\},?$",new_expr)
    if not match: sys.exit("Missing provider restriction: "+symbol)
    row=match.group(0)
    new_expr=replace_checked(new_expr,row,row.replace(", 1 }",", RESTRICTED_FILE_FUNC }"))
for opname in ["d","e","f","s","L","h","x"]:
    pattern='\\\"'+opname+'\\\", NULL,             1 }'
    # Use literal table value, no regex cross-file changes.
    if new_expr.count(pattern)!=1:
        # whitespace differs on the 7 entries; use a narrow regex instead
        match=re.search(r'(?m)^([ \\t]*\\{ op_file_[^\\n]+, "'+opname+r'", NULL,)[ \\t]*1 \\},?
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
    sys.exit("Missing expression flag after native dependency port")
add(port_names[2], native_diff("modules/ssl/ssl_engine_config.c",old,
                              old.replace(anchor,addendum), "CVE-2026-59797"))

date=datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
entry=("apache2 ("+version+") bionic; urgency=medium\n\n"
       "  * Experimental selective security backport; not ESM-equivalent.\n"
       "  * Import CVE-2026-63292 and CVE-2026-56153 unchanged.\n"
       "  * Native Bionic ports of CVE-2026-56154, CVE-2026-44119 and CVE-2026-59797.\n\n"
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
,new_expr)
        if not match: sys.exit("Missing unary file test "+opname)
        row=match.group(0)
        new_expr=replace_checked(new_expr,row,re.sub(r'1( \\},?)
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
,r'RESTRICTED_FILE_TEST\\1',row))
    else:
        new_expr=replace_checked(new_expr,pattern,pattern.replace("1 }","RESTRICTED_FILE_TEST }"))
new_expr=replace_checked(new_expr,
    "                    if ((parms->flags & AP_EXPR_FLAG_RESTRICTED)\\n"
    "                        && prov->restricted) {",
    "                    if (((parms->flags & AP_EXPR_FLAG_RESTRICTED)\\n"
    "                         && (prov->restricted & RESTRICTED_ALL))\\n"
    "                        || ((parms->flags & AP_EXPR_FLAG_RESTRICTED_FILE_FUNC)\\n"
    "                            && (prov->restricted & RESTRICTED_FILE_FUNC))) {")
vendor_expr=(vendor/"debian/patches/CVE-2026-44119.patch").read_text(encoding="utf-8")
if "RESTRICTED_FILE_FUNC" not in vendor_expr or "RESTRICTED_ALL" not in vendor_expr:
    sys.exit("Unexpected vendor expression-security patch")
p_expr=("Description: Native Bionic port of CVE-2026-44119; preserve the upstream\\n"
        " file-content restrictions in .htaccess and expression lookups.\\n"
        "Origin: Ubuntu Jammy apache2 2.4.52-1ubuntu4.27\\n"
        "Forwarded: not-needed\\n---\\n")
p_expr+=native_diff("include/ap_expr.h",old_header,new_header,"CVE-2026-44119").split("---\\n",1)[1]
p_expr+=native_diff("server/util_expr_eval.c",old_expr,new_expr,"CVE-2026-44119").split("---\\n",1)[1]
add(port_names[1],p_expr)

# Port of CVE-2026-59797: SSLRequire restricted-file-functions flag.
# Its parser implementation is provided by the preceding native dependency.
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
