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
    if name == "mod_proxy_hcheck_jammy_fix_to_detect_support.patch":
        # Upstream moves AJP optional-hook discovery from post_config
        # into child_init, where dependent modules have registered hooks.
        # Rebase the complete move, not the empty extraneous file hunk.
        upstream_patch = upstream.read_text()
        rel_path = "modules/proxy/mod_proxy_hcheck.c"
        if (upstream_patch.count("--- a/" + rel_path + "\n") != 1
                or upstream_patch.count("+++ b/" + rel_path + "\n") != 1
                or upstream_patch.count(
                    "+    ajp_handle_cping_cpong = "
                    "APR_RETRIEVE_OPTIONAL_FN(ajp_handle_cping_cpong);\n") != 1
                or upstream_patch.count(
                    "-    ajp_handle_cping_cpong = "
                    "APR_RETRIEVE_OPTIONAL_FN(ajp_handle_cping_cpong);\n") != 1):
            sys.exit("Unexpected upstream hcheck optional AJP hook move")
        path = focal / rel_path
        before = path.read_text()
        # Apache 2.4.41 Focal does not contain the later AJP optional-hook
        # discovery implementation being moved by this Jammy patch.
        # CPING exists in the proxy enum, but that alone does not make this
        # relocation valid. Explicitly skip rather than invent a feature.
        if "APR_RETRIEVE_OPTIONAL_FN(ajp_handle_cping_cpong)" not in before:
            decisions.append((
                name, "skipped",
                "Focal mod_proxy_hcheck lacks AJP optional-hook detection "
                "block; Jammy relocation is not directly applicable"
            ))
            continue
        hook = (
            "    ajp_handle_cping_cpong = APR_RETRIEVE_OPTIONAL_FN(ajp_handle_cping_cpong);\n"
            "    if (ajp_handle_cping_cpong) {\n"
            "       proxy_hcmethods_t *method = proxy_hcmethods;\n"
            "       for (; method->name; method++) {\n"
            "           if (method->method == CPING) {\n"
            "               method->implemented = 1;\n"
            "               break;\n"
            "           }\n"
            "       }\n"
            "    }\n"
        )
        # Move only if the exact old code is present once. Never copy
        # the extra file named *.patch accidentally included upstream.
        if before.count(hook) != 1:
            sys.exit("Focal hcheck old AJP detection block not unique")
        target = ("    hctp = NULL;\n"
                  "    tpsize = HC_THREADPOOL_SIZE;\n"
                  "#endif\n")
        if before.count(target) != 1:
            sys.exit("Focal hcheck child-init insertion anchor not unique")
        without = before.replace(hook + "\n", "", 1)
        if without == before:
            sys.exit("Focal hcheck old hook block has unexpected whitespace")
        after = without.replace(target, target + "\n" + hook + "\n", 1)
        if after.count(hook) != 1:
            sys.exit("AJP detection relocation did not preserve unique hook")
        rebased = "".join(difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="a/" + rel_path, tofile="b/" + rel_path, n=3
        ))
        if (not rebased.startswith("--- a/" + rel_path + "\n")
                or rebased.count("+" + hook.splitlines()[0] + "\n") != 1
                or rebased.count("-" + hook.splitlines()[0] + "\n") != 1):
            sys.exit("Incomplete hcheck relocation diff")
        patch_for_apply = out / "adapted-mod_proxy_hcheck_jammy_fix_to_detect_support.patch"
        patch_for_apply.write_text(rebased)
    if name == "CVE-2026-48913.patch":
        # Retain the full 24-file HTTP/2 patch. The only initial fuzz=0
        # conflicts are an SSL detection symbol in h2_c1_io.c and the
        # unavailable Jammy string comparator in h2_c2_filter.c. Rebase
        # those exact lines without removing any other patch section.
        source = upstream.read_text()
        expected_paths = (
            "modules/http2/h2_c1_io.c",
            "modules/http2/h2_c2_filter.c",
            "modules/http2/mod_proxy_http2.c",
        )
        if (len(re.findall(r"(?m)^--- a/modules/http2/", source)) != 24
                or any(source.count("--- a/" + path + "\n") != 1
                       for path in expected_paths)):
            sys.exit("Unexpected CVE-2026-48913 complete HTTP/2 file set")
        old_tls = "-    io->is_tls = ap_ssl_conn_is_ssl(session->c1);\n"
        new_tls = "-    io->is_tls = h2_h2_is_tls(session->c1);\n"
        if source.count(old_tls) != 1:
            sys.exit("Unexpected HTTP/2 TLS check in CVE-2026-48913")
        source = source.replace(old_tls, new_tls, 1)
        # The upstream fix chooses bytewise case-insensitive comparison
        # rather than locale/natural sorting. Focal has strcasecmp() but
        # does not expose ap_cstr_casecmp() in its older source APIs.
        for old, new in (
            ("+            if (*strpp && ap_cstr_casecmp(*strpp, start) == 0) {\n",
             "+            if (*strpp && strcasecmp(*strpp, start) == 0) {\n"),
            ("+                if (!ap_cstr_casecmp(token, languages[i]))\n",
             "+                if (!strcasecmp(token, languages[i]))\n"),
        ):
            if source.count(old) != 1:
                sys.exit("Unexpected HTTP/2 comparator patch layout: " + old.strip())
            source = source.replace(old, new, 1)
        # The initial Content-Language pointer fix was already imported in
        # CVE-2026-43951. Keep its context and the second hunk intact.
        if "CVE-2026-43951.patch" not in current:
            sys.exit("CVE-2026-48913 requires prior Content-Language fix")
        patch_for_apply = out / "adapted-CVE-2026-48913.patch"
        patch_for_apply.write_text(source)
    if name == "reenable-workers-in-standard-error-state-jammy-apache2.patch":
        # Backport both functional changes while retaining Focal's MMN.
        # Jammy's minor bump covers unrelated new hcmethod_t enums: Focal
        # cannot advertise that newer API. The added macro is only a status
        # bit test and does not change proxy worker structs or binary ABI.
        upstream_diff = upstream.read_text()
        expected = (
            "+#define PROXY_WORKER_IS_ERROR(f)   ( (f)->s->status &  PROXY_WORKER_IN_ERROR )",
            "+    else if (PROXY_WORKER_IS_HCFAILED(worker) || PROXY_WORKER_IS_ERROR(worker)) {",
            "+#define MODULE_MAGIC_NUMBER_MINOR 126",
        )
        if any(upstream_diff.count(x) != 1 for x in expected):
            sys.exit("Unexpected proxy hcheck worker recovery upstream patch")
        paths = ("modules/proxy/mod_proxy.h",
                 "modules/proxy/mod_proxy_hcheck.c")
        edits = []
        header_old = (
            "#define PROXY_WORKER_IS_HCFAILED(f)   ( (f)->s->status &  PROXY_WORKER_HC_FAIL )\n"
            "\n"
            "#define PROXY_WORKER_IS(f, b)"
        )
        header_new = (
            "#define PROXY_WORKER_IS_HCFAILED(f)   ( (f)->s->status &  PROXY_WORKER_HC_FAIL )\n"
            "\n"
            "#define PROXY_WORKER_IS_ERROR(f)   ( (f)->s->status &  PROXY_WORKER_IN_ERROR )\n"
            "\n"
            "#define PROXY_WORKER_IS(f, b)"
        )
        hcheck_old = "if (PROXY_WORKER_IS_HCFAILED(worker)) {"
        hcheck_new = ("if (PROXY_WORKER_IS_HCFAILED(worker) "
                      "|| PROXY_WORKER_IS_ERROR(worker)) {")
        for rel_path, old, new in (
                (paths[0], header_old, header_new),
                (paths[1], hcheck_old, hcheck_new)):
            source = (focal / rel_path).read_text()
            if source.count(old) != 1 or new in source:
                sys.exit("Cannot uniquely adapt proxy worker recovery: " + rel_path)
            adapted = source.replace(old, new, 1)
            diff = "".join(difflib.unified_diff(
                source.splitlines(keepends=True),
                adapted.splitlines(keepends=True),
                fromfile="a/" + rel_path, tofile="b/" + rel_path,
                n=3
            ))
            if (not diff.startswith("--- a/" + rel_path + "\n")
                    or (rel_path == paths[1]
                        and diff.count(
                            "+    if (PROXY_WORKER_IS_HCFAILED(worker) "
                            "|| PROXY_WORKER_IS_ERROR(worker)) {\n") != 1)):
                sys.exit("Failed proxy worker recovery diff: " + rel_path)
            edits.append(diff)
        # Ensure no change to the public ABI/MMN.
        mmn = (focal / "include/ap_mmn.h").read_text()
        if "MODULE_MAGIC_NUMBER_MINOR" not in mmn:
            sys.exit("Missing Focal module magic declaration")
        patch_for_apply = out / "adapted-reenable-workers-in-standard-error-state.patch"
        patch_for_apply.write_text("".join(edits))
    if name == "fix-a-possible-listener-deadlock.patch":
        # Import all six upstream changes atomically against Focal's event MPM.
        # Unlike Jammy, Focal connections_above_limit() takes no arguments.
        # Rebase the complete functional changes, not individual successful
        # hunks; the helper/wakeup/worker-shutdown edits depend on each other.
        upstream_diff = upstream.read_text()
        expected_upstream = (
            "+static APR_INLINE int should_enable_listensocks(void)",
            "+    return !dying && listeners_disabled() && !connections_above_limit(NULL);",
            "+                || should_enable_listensocks())) {",
            "+        if (!workers_were_busy && should_enable_listensocks()) {",
            "+    for (;;) {",
            "+            if (listener_is_wakeable && should_enable_listensocks()) {",
            "+                if (ps->quiescing != 2)",
        )
        if (upstream_diff.count("--- a/server/mpm/event/event.c\n") != 1
                or upstream_diff.count("+++ b/server/mpm/event/event.c\n") != 1
                or len(re.findall(r"(?m)^@@ -", upstream_diff)) != 6
                or any(upstream_diff.count(line) != 1 for line in expected_upstream)):
            sys.exit("Unexpected upstream listener deadlock patch structure")
        rel_path = "server/mpm/event/event.c"
        before = (focal / rel_path).read_text()
        after = before

        def replace_event(old, new, label):
            global after
            if after.count(old) != 1:
                sys.exit("Listener deadlock adaptation anchor mismatch for "
                         + label + ": " + str(after.count(old)))
            after = after.replace(old, new, 1)

        # Source order matters: all substitutions use exact existing Focal
        # context and are checked before any quilt patch is applied.
        helper_anchor = "static void abort_socket_nonblocking("
        helper = (
            "static APR_INLINE int should_enable_listensocks(void)\n"
            "{\n"
            "    return !dying && listeners_disabled() && !connections_above_limit();\n"
            "}\n\n"
        )
        if "static APR_INLINE int should_enable_listensocks(void)" in after:
            sys.exit("Focal already contains listener wakeup helper")
        replace_event(helper_anchor, helper + helper_anchor, "helper")
        replace_event(
            "                || (listeners_disabled() && !connections_above_limit()))) {",
            "                || should_enable_listensocks())) {",
            "close-connection wakeup")
        replace_event(
            "        if (listeners_disabled()\n"
            "                && !workers_were_busy\n"
            "                && !connections_above_limit()) {\n",
            "        if (!workers_were_busy && should_enable_listensocks()) {\n",
            "listener reenable")
        worker_start = "static void *APR_THREAD_FUNC worker_thread("
        if after.count(worker_start) != 1:
            sys.exit("Event worker thread not unique")
        worker_index = after.index(worker_start)
        loop_old = "    while (!workers_may_exit) {\n"
        loop_pos = after.find(loop_old, worker_index)
        if loop_pos < 0:
            sys.exit("Missing event worker shutdown loop")
        after = after[:loop_pos] + "    for (;;) {\n" + after[loop_pos+len(loop_old):]
        replace_event(
            "                signal_threads(ST_GRACEFUL);\n"
            "                break;\n"
            "            }\n"
            "            is_idle = 1;\n",
            "                signal_threads(ST_GRACEFUL);\n"
            "                break;\n"
            "            }\n"
            "            /* A new idler may have changed connections_above_limit(),\n"
            "             * let the listener know and decide.\n"
            "             */\n"
            "            if (listener_is_wakeable && should_enable_listensocks()) {\n"
            "                apr_pollset_wakeup(event_pollset);\n"
            "            }\n"
            "            is_idle = 1;\n",
            "worker-idle wakeup")
        replace_event(
            "                if (!ps->quiescing)\n"
            "                    active_daemons--;\n",
            "                if (ps->quiescing != 2)\n"
            "                    active_daemons--;\n",
            "child exit accounting")
        # Verify full upstream intent, not only individual line matches.
        if (after.count("static APR_INLINE int should_enable_listensocks(void)") != 1
                or after.count("should_enable_listensocks()") != 3
                or "                if (ps->quiescing != 2)" not in after
                or after.count("    for (;;) {\n") < before.count("    for (;;) {\n") + 1):
            sys.exit("Incomplete event listener deadlock adaptation")
        rebased = "".join(difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="a/" + rel_path, tofile="b/" + rel_path, n=3
        ))
        if not rebased.startswith("--- a/" + rel_path + "\n"):
            sys.exit("Cannot produce full event listener deadlock diff")
        patch_for_apply = out / "adapted-fix-a-possible-listener-deadlock.patch"
        patch_for_apply.write_text(rebased)
    if name == "handle-children-killed-pathologically.patch":
        # The two upstream first hunks add a single function-local counter,
        # but Focal server_main_loop() has a different signature. Rebase that
        # declaration by function identity while preserving EACH full second
        # upstream hunk (restart/anti-fork-storm logic) unmodified.
        import tempfile
        upstream_text = upstream.read_text()
        files = ("server/mpm/event/event.c", "server/mpm/worker/worker.c")
        rebased_diffs = []
        expected_added = "+    int successive_kills = 0;\n"
        for rel_path in files:
            begin = upstream_text.find("--- a/" + rel_path + "\n")
            end_header = upstream_text.find("+++ b/" + rel_path + "\n", begin)
            if begin < 0 or end_header < 0:
                sys.exit("Missing MPM patch file section: " + rel_path)
            first = re.search(
                r"(?m)^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@[^\n]*\n",
                upstream_text[end_header:]
            )
            if not first:
                sys.exit("Missing initial MPM hunk: " + rel_path)
            first_pos = end_header + first.start()
            second = re.search(
                r"(?m)^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@[^\n]*\n",
                upstream_text[first_pos + 3:]
            )
            if not second:
                sys.exit("Missing restart MPM hunk: " + rel_path)
            second_pos = first_pos + 3 + second.start()
            # Ubuntu uses plain unified diffs here, not necessarily
            # 'diff --git' separators. Stop at the next file header;
            # otherwise event.c's second hunk includes worker.c too.
            next_headers = [
                position for position in (
                    upstream_text.find("\n--- a/", second_pos),
                    upstream_text.find("\ndiff --git ", second_pos),
                ) if position >= 0
            ]
            end_file = min(next_headers) + 1 if next_headers else len(upstream_text)
            first_hunk = upstream_text[first_pos:second_pos]
            second_hunk = upstream_text[second_pos:end_file]
            # Check the actual security/restart changes rather than brittle
            # substring counts (which depend on upstream comment wording).
            required_restart = (
                "+            if (++successive_kills >= 3) {",
                "+            ++remaining_children_to_start;",
                "+            successive_kills = 0;",
                "+        if (remaining_children_to_start) {",
            )
            if (expected_added not in first_hunk
                    or any(line not in second_hunk
                           for line in required_restart)
                    or second_hunk.count("\n@@ ") != 0):
                sys.exit(
                    "Unexpected MPM restart patch structure in " + rel_path
                    + ": counter=" + str(expected_added in first_hunk)
                    + ", restart=" + str([line in second_hunk
                                         for line in required_restart])
                    + ", second header=" + second_hunk.splitlines()[0]
                )
            original_src = (focal / rel_path).read_text()
            # Patch the complete upstream restart hunk in isolation. We do
            # not loosen context or accept fuzz; copying into a temporary
            # tree prevents any partial modifications to the build source.
            with tempfile.TemporaryDirectory() as temp_root:
                temp = pathlib.Path(temp_root)
                dest = temp / rel_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(original_src)
                retained_patch = temp / "upstream-restart.patch"
                retained_patch.write_text(
                    "--- a/" + rel_path + "\n"
                    "+++ b/" + rel_path + "\n" + second_hunk
                )
                check = subprocess.run(
                    ["patch", "--batch", "--forward", "--fuzz=0",
                     "-p1", "-i", str(retained_patch)],
                    cwd=temp, text=True, capture_output=True, timeout=60
                )
                if check.returncode:
                    sys.exit("Upstream MPM restart logic cannot be rebased: "
                             + rel_path + "\n" + check.stdout + check.stderr)
                after = dest.read_text()
            signature = re.compile(
                r"(?m)^static void server_main_loop\([^\n]*\)\n\{\n"
            )
            if len(signature.findall(after)) != 1:
                sys.exit("Focal MPM server_main_loop signature ambiguous: " + rel_path)
            after = signature.sub(
                lambda match: match.group(0) + "    int successive_kills = 0;\n",
                after, count=1
            )
            if after.count("int successive_kills = 0;") != 1:
                sys.exit("MPM successive kill counter missing or duplicated")
            diff = "".join(difflib.unified_diff(
                original_src.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile="a/" + rel_path, tofile="b/" + rel_path, n=3
            ))
            if (not diff.startswith("--- a/" + rel_path + "\n")
                    or diff.count("+    int successive_kills = 0;") != 1
                    or 'children are killed successively!' not in diff):
                sys.exit("MPM full-fix diff incomplete: " + rel_path)
            rebased_diffs.append(diff)
        patch_for_apply = out / "adapted-handle-children-killed-pathologically.patch"
        patch_for_apply.write_text("".join(rebased_diffs))
    if name == "CVE-2026-43951.patch":
        # Both HTTP/1.x and HTTP/2 need this same OOB-read fix. The
        # content_languages array can grow inside the while loop, so its
        # element pointer must be reloaded after each potential reallocation.
        # Rebuild only the two tiny upstream hunks using exact Focal context.
        original = upstream.read_text()
        removed = "-        char **languages = (char **)(r->content_languages->elts);"
        added = "+            char **languages = (char **)(r->content_languages->elts);"
        expected_files = (
            "modules/http/http_filters.c",
            "modules/http2/h2_c2_filter.c",
        )
        if (original.count(removed) != 2
                or original.count(added) != 2
                or original.count("--- a/") != 2
                or original.count("+++ b/") != 2
                or any(original.count("--- a/" + item + "\n") != 1
                       for item in expected_files)
                or any(original.count("+++ b/" + item + "\n") != 1
                       for item in expected_files)):
            sys.exit("Unexpected upstream CVE-2026-43951 patch content")
        generated = []
        declaration = "        char **languages = (char **)(r->content_languages->elts);\n"
        loop = ("        while (field && (token = "
                "ap_get_list_item(r->pool, &field)) != NULL) {\n")
        field = ('        const char *field = '
                 'apr_table_get(r->headers_out, "Content-Language");\n')
        for rel_path in expected_files:
            rel = pathlib.Path(rel_path)
            before = (focal / rel).read_text()
            # Validate the entire declaration-to-loop sequence, not an
            # arbitrary nearby occurrence or approximate patch context.
            old = declaration + field + "\n" + loop
            new = field + "\n" + loop + "    " + declaration
            if before.count(old) != 1:
                sys.exit("Cannot uniquely rebase CVE-2026-43951 in " + rel_path)
            after = before.replace(old, new, 1)
            candidate = "".join(difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile="a/" + rel_path, tofile="b/" + rel_path,
                n=3,
            ))
            if (candidate.count("-" + declaration) != 1
                    or candidate.count("+" + "    " + declaration) != 1):
                sys.exit("Unexpected CVE-2026-43951 rebase in " + rel_path)
            generated.append(candidate)
        patch_for_apply = out / "adapted-CVE-2026-43951.patch"
        patch_for_apply.write_text("".join(generated))
    if name == "CVE-2026-7363X.patch":
        # Port the entire patched Jammy Digest implementation at once. Nine
        # conflicting hunks in Focal cannot be applied in isolation: nonce,
        # client-state locking and authentication flow must remain coordinated.
        # Jammy's source has already received the complete quilt series from
        # apt-get source. Keep other Focal modules untouched and retain this
        # adaptation as a reviewable, exact zero-fuzz quilt diff.
        rel = pathlib.Path("modules/aaa/mod_auth_digest.c")
        focal_before = (focal / rel).read_text()
        jammy_after = (jammy / rel).read_text()
        required = ("check_and_record_nonce", "client_generate",
                    "client_exists", "APR_HAS_SHARED_MEMORY",
                    "apr_atomic")
        if (any(token not in jammy_after for token in required)
                or "check_and_record_nonce" in focal_before):
            sys.exit("Digest security source not in expected pre/post-patch state")
        # Focal uses standard strcasecmp(), unlike the newer ap_cstr_casecmp()
        # helper in Jammy. Its comparison semantics are equivalent here.
        jammy_after = re.sub(r"\bap_cstr_casecmp\s*\(", "strcasecmp(",
                             jammy_after)
        # Preserve the upstream APR random+shared-memory configure prerequisite.
        # The source-level #error alone does not prevent autoconf from enabling
        # an unsupported module on a different APR build.
        configure_rel = pathlib.Path("modules/aaa/config.m4")
        focal_config = (focal / configure_rel).read_text()
        old_config = (
            '  if test $ac_cv_define_APR_HAS_RANDOM = "no"; then\\n'
            '    echo "You need APR random support to use mod_auth_digest."\\n'
            '    echo "Look at APR configure options --with-egd and --with-devrandom."\\n'
        )
        new_config = (
            '  APR_CHECK_APR_DEFINE(APR_HAS_SHARED_MEMORY)\\n'
            '  if test "${ac_cv_define_APR_HAS_RANDOM}X${ac_cv_define_APR_HAS_SHARED_MEMORY}" != "yesXyes"; then\\n'
            '    AC_MSG_NOTICE([mod_auth_digest requires APR with random and shared memory support])\\n'
        )
        # Actual newlines (not backslash-n text) are required in config.m4.
        old_config = old_config.replace("\\n", "\n")
        new_config = new_config.replace("\\n", "\n")
        if focal_config.count(old_config) != 1:
            sys.exit("Digest configure APR prerequisite cannot be adapted exactly")
        config_after = focal_config.replace(old_config, new_config, 1)
        module_diff = "".join(difflib.unified_diff(
            focal_before.splitlines(keepends=True),
            jammy_after.splitlines(keepends=True),
            fromfile="a/" + str(rel), tofile="b/" + str(rel), n=3,
        ))
        config_diff = "".join(difflib.unified_diff(
            focal_config.splitlines(keepends=True),
            config_after.splitlines(keepends=True),
            fromfile="a/" + str(configure_rel),
            tofile="b/" + str(configure_rel), n=3,
        ))
        if not module_diff.startswith("--- a/modules/aaa/mod_auth_digest.c") or not config_diff.startswith("--- a/modules/aaa/config.m4"):
            sys.exit("Complete Digest security diff not generated")
        patch_for_apply = out / "adapted-CVE-2026-7363X.patch"
        patch_for_apply.write_text(config_diff + module_diff)
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
                      "Focal context adapted; see source diff (fuzz=0)"
                      if name in ("CVE-2026-44119.patch",
                                  "CVE-2024-43204-pre1.patch",
                                  "CVE-2024-43204.patch",
                                  "CVE-2025-23048-regression.patch",
                                  "CVE-2026-44631.patch",
                                  "CVE-2026-106023.patch",
                                  "CVE-2026-7363X.patch",
                                  "CVE-2026-43951.patch",
                                  "handle-children-killed-pathologically.patch",
                                  "mod_proxy_hcheck_jammy_fix_to_detect_support.patch",
                                  "fix-a-possible-listener-deadlock.patch",
                                  "reenable-workers-in-standard-error-state-jammy-apache2.patch",
                                  "CVE-2026-48913.patch")
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

# Focal-native hardening for mod_md renewal retry arithmetic.  The Jammy
# CVE-2025-55753 series contains many unrelated prerequisites that do not map
# to Focal 2.0.10; this small fix does NOT mark that CVE remediated.
# In particular a high, persistent error counter must not overflow int or
# perform an undefined shift before the one-hour cap is applied.
md_drive = focal / "modules/md/mod_md_drive.c"
before = md_drive.read_text()
old_backoff = "        delay = apr_time_from_sec(5 << (err_count - 1));"
new_backoff = (
    "        delay = (err_count >= 11)\n"
    "                ? apr_time_from_sec(60 * 60)\n"
    "                : apr_time_from_sec(5 << (err_count - 1));"
)
if before.count(old_backoff) != 1:
    sys.exit("Unexpected Focal mod_md backoff implementation; review required")
after = before.replace(old_backoff, new_backoff, 1)
mod_md_diff = "".join(difflib.unified_diff(
    before.splitlines(keepends=True),
    after.splitlines(keepends=True),
    fromfile="a/modules/md/mod_md_drive.c",
    tofile="b/modules/md/mod_md_drive.c",
))
md_patch_name = "unibo-focal-mod-md-bounded-backoff.patch"
md_dest = focal / "debian/patches" / md_patch_name
md_dest.write_text(mod_md_diff)
result = subprocess.run(
    ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(md_dest)],
    cwd=focal, text=True, capture_output=True, timeout=60,
)
if result.returncode:
    sys.exit("Could not apply Focal-native mod_md bound: " +
             result.stdout + result.stderr)
with series_path.open("a") as file:
    file.write(md_patch_name + "\n")
(out / "mod-md-bounded-backoff.patch").write_text(mod_md_diff)
assert new_backoff in md_drive.read_text()
# The cap is 3600s. The first overflowing/unbounded exponent is never reached.
assert (5 << 9) < 3600 and (5 << 10) > 3600

# CVE-2025-55753-3 is an upstream 2.6.6 -> 2.6.7 regression fix for
# MDStapleOthers (USN-7968-2). Confirm the new feature is absent from
# Focal's native mod_md 2.0.10; never transplant the OCSP fix in isolation.
md_source = focal / "modules/md"
md_files = list(md_source.glob("*.[ch]"))
feature_files = [str(path.relative_to(focal)) for path in md_files
                 if "MDStapleOthers" in path.read_text(errors="replace")]
if feature_files or (md_source / "mod_md_ocsp.c").exists() or (md_source / "md_ocsp.c").exists():
    sys.exit("OCSP/MDStapleOthers architecture differs from expected Focal baseline: "
             + ", ".join(feature_files))
(out / "mod-md-followup-disposition.md").write_text(
    "# CVE-2025-55753-3 applicability to Focal mod_md\n\n"
    "Ubuntu USN-7968-2 describes a regression of MDStapleOthers after "
    "updating mod_md to 2.6.6. Focal's native module is 2.0.10.\n\n"
    "- No MDStapleOthers directive is found in the Focal mod_md source.\n"
    "- Newer mod_md OCSP implementation units are absent.\n"
    "- The Focal-native renewal backoff fix is retained separately.\n\n"
    "Decision: do not import this newer-architecture regression fix.\n"
    "This is a feature applicability finding, NOT a blanket claim that "
    "Focal's certificate/OCSP implementation is free of vulnerabilities.\n"
)
# CVE-2026-29168 modifies the OCSP renewal engine md_ocsp.c, which
# does not exist in Focal mod_md 2.0.10. Verify exactly which paths the
# upstream patch changes, and reject any source architecture drift.
ocsp_patch = (jammy / "debian/patches/CVE-2026-29168.patch").read_text()
ocsp_paths = set(re.findall(r"(?m)^\+\+\+ b/(modules/md/[^\s]+)", ocsp_patch))
if ocsp_paths != {"modules/md/md_ocsp.c"}:
    sys.exit("Unexpected CVE-2026-29168 source footprint: " + repr(ocsp_paths))
ocsp_native = focal / "modules/md/md_ocsp.c"
if ocsp_native.exists() or (focal / "modules/md/mod_md_ocsp.c").exists():
    sys.exit("Focal mod_md has newer OCSP engine: reassess CVE-2026-29168")
(out / "mod-md-ocsp-disposition.md").write_text(
    "# CVE-2026-29168 applicability to Focal mod_md\n\n"
    "The exact Ubuntu Jammy patch modifies only modules/md/md_ocsp.c.\n"
    "This file and mod_md_ocsp.c are absent in native Focal mod_md 2.0.10.\n"
    "Decision: the patched newer OCSP renewal code path is not present; "
    "do not import the patch or newer architecture.\n\n"
    "This does NOT assess mod_ssl's distinct OCSP stapling implementation, "
    "nor does it establish that all certificate handling is secure.\n"
)
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
    f.write("\nCVE-2025-55753-3: upstream MDStapleOthers regression fix; "
            "the directive and newer OCSP implementation are absent in "
            "native Focal mod_md (verified by CI). Not imported.\n")
    f.write("\nCVE-2026-29168: the upstream patch exclusively changes "
            "modules/md/md_ocsp.c, absent from native Focal mod_md "
            "(verified by CI). Not imported; mod_ssl OCSP is separate.\n")
    f.write("\nAdditional Focal-only hardening (not counted as a Jammy CVE fix): "
            + md_patch_name + ". CVE-2025-55753 remains excluded.\n")
    f.write("\nNext: review each source diff, add prerequisite patches and complete "
            "missing CVEs, then run regression and ABI tests.\n")
print(f"Applied {len(accepted)} candidate patches, skipped {len(skipped)}")
