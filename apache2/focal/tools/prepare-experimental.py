#!/usr/bin/env python3
"""Create an EXPERIMENTAL Ubuntu Focal Apache source tree carrying Jammy patches.

Copies exact upstream Ubuntu Jammy quilt patches and applies only clean,
zero-fuzz patches in original Jammy series order. It produces a manifest of
skips. This does not establish complete CVE coverage or patch correctness.
"""
import datetime
import difflib
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
        expected = {"CVE-2024-43204-pre1.patch": 5,
                    "CVE-2024-43204.patch": 2}[name]
        if count != expected:
            sys.exit(f"Unexpected mod_headers patch layout for {name}: "
                     f"expected {expected} comparator calls, found {count}")
        patched = original.replace(jammy_cmp, focal_cmp)
        patch_for_apply = out / ("adapted-" + name)
        patch_for_apply.write_text(patched)
    if name == "CVE-2024-42516.patch":
        # The final Jammy hunk carries unrelated response-header context
        # absent in Focal. Rebase ONLY that hunk to remove the same original
        # keepalive sequence, without changing any security-sensitive code.
        original = upstream.read_text()
        old_calls = (
            "    /* determine the protocol and whether we should use keepalives. */\n"
            "    basic_http_header_check(r, &protocol);\n"
            "    ap_set_keepalive(r);\n"
            "\n"
        )
        http_src = (focal / "modules/http/http_filters.c").read_text()
        if http_src.count(old_calls) != 1:
            sys.exit("Cannot safely adapt CVE-2024-42516: keepalive block not unique")
        hunk_headers = list(re.finditer(
            r"(?m)^@@ -[0-9]+(?:,[0-9]+)? \+[0-9]+(?:,[0-9]+)? @@[^\n]*\n",
            original,
        ))
        if len(hunk_headers) != 4:
            sys.exit("Unexpected CVE-2024-42516 hunk count: "
                     + str(len(hunk_headers)))
        removed = "".join("-" + line for line in old_calls.splitlines(keepends=True))
        matched = []
        for idx, hunk in enumerate(hunk_headers):
            hunk_end = (hunk_headers[idx + 1].start()
                        if idx + 1 < len(hunk_headers) else len(original))
            body = original[hunk.end():hunk_end]
            if removed in body:
                matched.append((hunk, hunk_end, body))
        if len(matched) != 1:
            sys.exit("CVE-2024-42516 keepalive deletion hunk not unique: "
                     + str(len(matched)))
        chosen, chosen_end, old_body = matched[0]
        if old_body.count(removed) != 1:
            sys.exit("Unexpected CVE-2024-42516 keepalive deletion content")
        if any(line.startswith("+") for line in old_body.splitlines()):
            sys.exit("Unexpected CVE-2024-42516 additions in keepalive hunk")
        if any(line.startswith("-") and line not in removed.splitlines()
               for line in old_body.splitlines()):
            sys.exit("Unexpected additional deletions in keepalive hunk")
        # Adapt only this one hunk. Preserve all remaining security changes.
        replacement = "@@ -1454,4 +1357,0 @@\n" + removed
        patched = (original[:chosen.start()] + replacement
                   + original[chosen_end:])
        # Focal's response serializer has an explicit 304 Not Modified
        # header allowlist, absent from Jammy's fourth hunk context.
        # Carry that allowlist into the refactored serializer unchanged.
        original_304_start = "    if (r->status == HTTP_NOT_MODIFIED) {\n"
        original_304_end = "    terminate_header(b2);\n"
        if http_src.count(original_304_start) != 1:
            sys.exit("Unexpected Focal 304 response-header handling")
        start_304 = http_src.index(original_304_start)
        end_304 = http_src.index(original_304_end, start_304)
        body_304 = http_src[start_304:end_304]
        if (body_304.count("send_all_header_fields(&h, r);") != 1
                or body_304.count("form_header_field") != 1
                or not body_304.endswith("    }\n\n")):
            sys.exit("Unexpected Focal 304 response header allowlist")
        # The upstream hunk already carries the blank context line after
        # the serializer. Copying the trailing blank from Focal as a deleted
        # line would duplicate it, preventing exact (fuzz=0) application.
        body_304 = body_304[:-1]
        assert body_304.endswith("    }\n")
        # The fourth hunk must retain the 304-specific header allowlist
        # in both removed and added sections, with only indentation changed.
        headers = list(re.finditer(
            r"(?m)^@@ -[0-9]+(?:,[0-9]+)? \+[0-9]+(?:,[0-9]+)? @@[^\n]*\n",
            patched,
        ))
        if len(headers) != 4:
            sys.exit("Unexpected adapted CVE-2024-42516 hunk count")
        fourth = headers[-1]
        fourth_body = patched[fourth.end():]
        old_single = "-    send_all_header_fields(&h, r);\n"
        new_single = "+        send_all_header_fields(&h, r);\n"
        if (fourth_body.count(old_single) != 1
                or fourth_body.count(new_single) != 1):
            sys.exit("CVE-2024-42516 serializer locations not unique")
        old_allowlist = "".join(
            "-" + line for line in body_304.splitlines(keepends=True)
        )
        new_allowlist = "".join(
            "+" + ("    " + line if line.strip() else line)
            for line in body_304.splitlines(keepends=True)
        )
        fourth_body = fourth_body.replace(old_single, old_allowlist, 1)
        fourth_body = fourth_body.replace(new_single, new_allowlist, 1)
        increase = len(body_304.splitlines()) - 1
        hunk_header = patched[fourth.start():fourth.end()]
        count_header = re.match(
            r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@(.*)\n",
            hunk_header,
        )
        if not count_header:
            sys.exit("CVE-2024-42516 fourth hunk header unexpected")
        a, b, c, d = map(int, count_header.groups()[:4])
        new_header = (
            f"@@ -{a},{b + increase} +{c},{d + increase} @@"
            + count_header.group(5) + "\n"
        )
        patched = patched[:fourth.start()] + new_header + fourth_body
        patch_for_apply = out / "adapted-CVE-2024-42516.patch"
        patch_for_apply.write_text(patched)
    if name == "CVE-2026-106023.patch":
        # Only mod_md.c differs: regenerate its hunk against the exact Focal
        # HTTP-01 handler. Keep the upstream md_core/status hunks unchanged.
        original = upstream.read_text()
        modmd_path = focal / "modules/md/mod_md.c"
        before = modmd_path.read_text()
        func = "static int md_http_challenge_pr(request_rec *r)"
        if before.count(func) != 1:
            sys.exit("Cannot safely adapt CVE-2026-106023: HTTP-01 handler not unique")
        fn_start = before.index(func)
        # The original patch guards the hostname before the first logging
        # and domain lookup in the configured HTTP-01 challenge handler.
        candidate = before[fn_start:]
        m = re.search(
            r"(?m)^([ \t]*)if \(sc && sc->mc\) \{\n"
            r"(?=[ \t]*ap_log_rerror\(APLOG_MARK, APLOG_TRACE1)",
            candidate,
        )
        if not m:
            sys.exit("Cannot safely adapt CVE-2026-106023: ACME guard anchor absent")
        if candidate.count("if (sc && sc->mc) {") != 1:
            sys.exit("Cannot safely adapt CVE-2026-106023: multiple HTTP-01 guards")
        indent = m.group(1) + "    "
        upstream_new = (
            "if (!r->hostname) {\n"
            "                /* No Host: (e.g. an HTTP/1.0 request without one) means no\n"
            "                 * domain to look up; leave the request to normal handling. */\n"
            "                return DECLINED;\n"
            "            }\n"
        )
        # Require the exact logic in the upstream CVE before incorporating it.
        expected_upstream = (
            "+            if (!r->hostname) {\n"
            "+                /* No Host: (e.g. an HTTP/1.0 request without one) means no\n"
            "+                 * domain to look up; leave the request to normal handling. */\n"
            "+                return DECLINED;\n"
            "+            }\n"
        )
        if original.count(expected_upstream) != 1:
            sys.exit("Unexpected CVE-2026-106023 security guard content")
        guard = "".join(indent + line.lstrip(" ") + "\n"
                        for line in upstream_new.splitlines())
        insertion_pos = fn_start + m.end()
        after = before[:insertion_pos] + guard + before[insertion_pos:]
        modmd_diff = "".join(difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="a/modules/md/mod_md.c",
            tofile="b/modules/md/mod_md.c",
            n=3,
        ))
        if not modmd_diff.startswith("--- a/modules/md/mod_md.c"):
            sys.exit("Could not generate mod_md HTTP-01 CVE guard")
        beginning = original.find("--- a/modules/md/mod_md.c\n")
        ending = original.find("--- a/modules/md/mod_md_status.c\n", beginning)
        if beginning < 0 or ending <= beginning:
            sys.exit("Unexpected CVE-2026-106023 multi-file patch layout")
        adapted = original[:beginning] + modmd_diff + original[ending:]
        patch_for_apply = out / "adapted-CVE-2026-106023.patch"
        patch_for_apply.write_text(adapted)
    if name == "CVE-2026-44631.patch":
        # Focal ap_regex.h omits two pre-existing doc lines present in
        # Jammy. Change ONLY patch context: all security-sensitive additions
        # and deletions in proxy/core/PCRE remain byte-for-byte unchanged.
        original = upstream.read_text()
        old_context = (
            "@@ -189,6 +189,8 @@ AP_DECLARE(apr_size_t) ap_regerror(int e\n"
            "  * @param prefix An optional prefix to add to the returned names.  AP_REG_MATCH\n"
            "  * is the recommended prefix.\n"
            "  * @param upper If non zero, uppercase the names\n"
        )
        new_context = (
            "@@ -189,4 +189,6 @@ AP_DECLARE(apr_size_t) ap_regerror(int e\n"
            "  * @param upper If non zero, uppercase the names\n"
        )
        focal_header = (focal / "include/ap_regex.h").read_text()
        if (original.count(old_context) != 1
                or focal_header.count(" * @param upper If non zero, uppercase the names") != 1
                or " * @param prefix An optional prefix" in focal_header):
            sys.exit("Cannot safely adapt CVE-2026-44631 header documentation")
        patch_for_apply = out / "adapted-CVE-2026-44631.patch"
        patch_for_apply.write_text(original.replace(old_context, new_context, 1))
    if name == "CVE-2025-23048-regression.patch":
        # Ubuntu Jammy has an SSLKEYLOGFILE field that is absent from Focal.
        # Anchor the new SNI policy field on the shared struct closing line,
        # leaving the complete security implementation otherwise unchanged.
        original = upstream.read_text()
        old_hunk = (
            "@@ -628,6 +641,8 @@ typedef struct {\n"
            "     /* Used for logging if SSLKEYLOGFILE is set at startup. */\n"
            "     apr_file_t      *keylog_file;\n"
            " #endif\n"
            "+\n"
            "+    modssl_snivhpolicy_t snivh_policy;\n"
            " } SSLModConfigRec;\n"
        )
        new_hunk = (
            "@@ -620,1 +633,3 @@ typedef struct {\n"
            "+\n"
            "+    modssl_snivhpolicy_t snivh_policy;\n"
            " } SSLModConfigRec;\n"
        )
        focal_ssl_header = (focal / "modules/ssl/ssl_private.h").read_text()
        if (original.count(old_hunk) != 1
                or focal_ssl_header.count("} SSLModConfigRec;") != 1
                or "modssl_snivhpolicy_t snivh_policy;" in focal_ssl_header):
            sys.exit("Unexpected SSLModConfigRec structure in CVE-2025-23048 regression")
        # ssl_init_Module references sni_policy_hash outside HAVE_TLSEXT.
        # Focal must retain this struct member in both preprocessor modes.
        old_hash_hunk = (
            "     ssl_enabled_t    strict_sni_vhost_check;\n"
            "+    const char      *sni_policy_hash;\n"
            " #endif\n"
        )
        new_hash_hunk = (
            "     ssl_enabled_t    strict_sni_vhost_check;\n"
            " #endif\n"
            "+    const char      *sni_policy_hash;\n"
        )
        if original.count(old_hash_hunk) != 1:
            sys.exit("Unexpected sni_policy_hash placement in SNI regression patch")
        original = original.replace(old_hash_hunk, new_hash_hunk, 1)
        patch_for_apply = out / "adapted-CVE-2025-23048-regression.patch"
        patch_for_apply.write_text(original.replace(old_hunk, new_hunk, 1))
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
    if name == "CVE-2024-42516.patch" and check.returncode:
        # Fail closed, but expose the complete 4-hunk diff and failing
        # source context to make the next explicit rebase reviewable.
        patch_text = patch_for_apply.read_text(errors="replace")
        print("=== CVE-2024-42516 adapted patch (complete) ===",
              file=sys.stderr, flush=True)
        print(patch_text[-18000:], file=sys.stderr, flush=True)
        print("=== CVE-2024-42516 Focal response-header context ===",
              file=sys.stderr, flush=True)
        lines = (focal / "modules/http/http_filters.c").read_text(
            errors="replace").splitlines()
        for index, line in enumerate(lines, 1):
            if 1300 <= index <= 1580:
                print(f"{index}: {line}", file=sys.stderr)
        sys.exit("Required CVE-2024-42516 patch not applied (fuzz=0): "
                 + check.stdout.strip()[-2400:])
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
                                  "CVE-2024-43204.patch",
                                  "CVE-2025-23048-regression.patch",
                                  "CVE-2026-44631.patch",
                                  "CVE-2026-106023.patch",
                                  "CVE-2024-42516.patch")
                      else "zero-fuzz sequential patch"))
    current.add(name)

# Verify/repair the SNI hash member in the actual Focal structure.
# It is required by ssl_init_Module regardless of HAVE_TLSEXT.  Keep
# the Focal-only layout adjustment as a separate, auditable quilt patch.
if "CVE-2025-23048-regression.patch" in current:
    ssl_path = focal / "modules/ssl/ssl_private.h"
    ssl_header = ssl_path.read_text()
    start = ssl_header.find("struct SSLSrvConfigRec {")
    if start < 0:
        sys.exit("Missing SSLSrvConfigRec in patched Focal SSL header")
    end = ssl_header.find("};", start)
    if end < 0:
        sys.exit("Unterminated SSLSrvConfigRec")
    definition = ssl_header[start:end]
    member = "    const char      *sni_policy_hash;\n"
    anchor = ("#ifdef HAVE_TLSEXT\n"
              "    ssl_enabled_t    strict_sni_vhost_check;\n"
              "#endif\n")
    if definition.count(member) == 0:
        if ssl_header.count(member) != 0 or definition.count(anchor) != 1:
            sys.exit("Unexpected sni_policy_hash placement or SNI struct layout")
        before = ssl_header
        after = before[:start] + definition.replace(
            anchor, anchor + member, 1
        ) + before[end:]
        diff = "".join(difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="a/modules/ssl/ssl_private.h",
            tofile="b/modules/ssl/ssl_private.h",
        ))
        if not diff.startswith("--- a/modules/ssl/ssl_private.h"):
            sys.exit("Cannot generate SNI hash member patch")
        patch_name = "unibo-focal-sni-policy-hash-member.patch"
        dest = focal / "debian/patches" / patch_name
        dest.write_text(diff)
        result = subprocess.run(
            ["patch", "--batch", "--forward", "--fuzz=0", "-p1",
             "-i", str(dest)],
            cwd=focal, text=True, capture_output=True, timeout=60,
        )
        if result.returncode:
            sys.exit("Failed SNI hash layout backport: "
                     + result.stdout + result.stderr)
        with series_path.open("a") as file:
            file.write(patch_name + "\n")
        decisions.append((
            patch_name, "applied",
            "Focal-only SSLSrvConfigRec SNI policy hash member"
        ))
        ssl_header = ssl_path.read_text()
        definition = ssl_header[start:ssl_header.find("};", start)]
    if definition.count(member) != 1:
        sys.exit("SNI hash member missing or duplicated in SSLSrvConfigRec:\n"
                 + definition)
    strict = definition.find("strict_sni_vhost_check")
    if strict < 0 or not (
        strict < definition.find("#endif", strict)
        < definition.find(member)
    ):
        sys.exit("SNI hash member is not unconditional in SSLSrvConfigRec")
    (out / "sni-struct-check.txt").write_text(
        "Verified SNI policy hash field:\n" + definition + "\n"
    )

# Focal needs an explicit declaration visible at the point where mod_ssl.c
# registers SSLVHostSNIPolicy. Carry the compatibility-only change as its own
# auditable quilt patch rather than silently modifying an unpacked source.
if ("CVE-2025-23048-regression.patch" in current
        and "CVE-2025-23048-regression-2.patch" in current):
    ssl_conf = (focal / "modules/ssl/ssl_engine_config.c").read_text()
    assert "ssl_cmd_SSLVHostSNIPolicy(" in ssl_conf, (
        "SNI policy command registered without an implementation"
    )
    modssl_file = focal / "modules/ssl/mod_ssl.c"
    before = modssl_file.read_text()
    signature = ("const char *ssl_cmd_SSLVHostSNIPolicy("
                 "cmd_parms *cmd, void *dcfg, const char *arg);")
    location = "static const command_rec ssl_config_cmds"
    assert before.count(location) == 1
    if signature not in before:
        after = before.replace(location, signature + "\n\n" + location, 1)
        diff = "".join(difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="a/modules/ssl/mod_ssl.c",
            tofile="b/modules/ssl/mod_ssl.c",
        ))
        assert diff.startswith("--- a/modules/ssl/mod_ssl.c")
        name = "unibo-focal-sni-command-declaration.patch"
        dest = focal / "debian/patches" / name
        dest.write_text(diff)
        result = subprocess.run(
            ["patch", "--batch", "--forward", "--fuzz=0", "-p1",
             "-i", str(dest)],
            cwd=focal, text=True, capture_output=True, timeout=60,
        )
        if result.returncode:
            sys.exit("Failed SNI command declaration backport: "
                     + result.stdout + result.stderr)
        with series_path.open("a") as file:
            file.write(name + "\n")
        decisions.append((
            name, "applied",
            "Focal-only prototype for SNI directive; regression-1/2 required"
        ))

# The SNI policy feature must not be delivered without its strict-policy
# regression fix. Abort rather than packaging a partially corrected policy.
if ("CVE-2025-23048-regression.patch" in current
        and "CVE-2025-23048-regression-2.patch" not in current):
    sys.exit("SNI policy regression patch incomplete: missing regression-2")

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
