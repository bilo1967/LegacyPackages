# Jammy patches against Focal 2.4.41 (independent dry runs)

**Not a security validation.** All checks run independently against the unmodified, already-patched Focal source. A failure may reflect missing prerequisite patches; success does not establish functionality, patch order, CVE coverage, or compatibility.

Patch candidates: 65

- DRY_RUN_OK: 42
- POSSIBLY_APPLIED: 2
- NEEDS_REVIEW: 21
- MISSING: 0
- TIMEOUT: 0

| Candidate | Result | Output excerpt |
|---|---|---|
| `fix-macro.patch` | DRY_RUN_OK | File modules/core/mod_macro.c is read-only; trying to patch anyway; checking file modules/core/mod_macro.c |
| `fix-a-possible-listener-deadlock.patch` | NEEDS_REVIEW | Hunk #4 succeeded at 2008 (offset -58 lines).; Hunk #5 succeeded at 2023 (offset -58 lines).; Hunk #6 FAILED at 3051.; 4 out of 6 hunks FAILED |
| `handle-children-killed-pathologically.patch` | NEEDS_REVIEW | checking file server/mpm/worker/worker.c; Hunk #1 FAILED at 1575.; Hunk #2 succeeded at 1657 (offset -12 lines).; 1 out of 2 hunks FAILED |
| `mod_proxy_hcheck_jammy_fix_to_detect_support.patch` | NEEDS_REVIEW | Hunk #1 FAILED at 1070.; Hunk #2 FAILED at 1126.; 2 out of 2 hunks FAILED; checking file mod_proxy_hcheck_jammy_fix_to_detect_support.patch |
| `reenable-workers-in-standard-error-state-jammy-apache2.patch` | NEEDS_REVIEW | File modules/proxy/mod_proxy_hcheck.c is read-only; trying to patch anyway; checking file modules/proxy/mod_proxy_hcheck.c; Hunk #1 FAILED at 909.; 1 out of 1 hunk FAILED |
| `CVE-2024-42516.patch` | NEEDS_REVIEW | Hunk #2 succeeded at 1330 (offset -3 lines).; Hunk #3 succeeded at 1352 (offset -3 lines).; Hunk #4 FAILED at 1415.; 1 out of 4 hunks FAILED |
| `CVE-2024-43204-pre1.patch` | NEEDS_REVIEW | Hunk #1 FAILED at 782.; Hunk #2 succeeded at 806 (offset 9 lines).; Hunk #3 succeeded at 822 (offset 9 lines).; 1 out of 3 hunks FAILED |
| `CVE-2024-43204.patch` | NEEDS_REVIEW | checking file modules/metadata/mod_headers.c; Hunk #1 FAILED at 784.; Hunk #2 FAILED at 792.; 2 out of 2 hunks FAILED |
| `CVE-2024-47252.patch` | DRY_RUN_OK | File modules/ssl/ssl_engine_vars.c is read-only; trying to patch anyway; checking file modules/ssl/ssl_engine_vars.c; Hunk #1 succeeded at 1230 (offset 23 lines).; Hunk #2 succeeded at 1245 (offset 23 lines). |
| `CVE-2025-23048.patch` | DRY_RUN_OK | File modules/ssl/ssl_engine_kernel.c is read-only; trying to patch anyway; checking file modules/ssl/ssl_engine_kernel.c |
| `CVE-2025-49630.patch` | DRY_RUN_OK | File modules/http2/h2_proxy_session.c is read-only; trying to patch anyway; checking file modules/http2/h2_proxy_session.c |
| `CVE-2025-49812.patch` | DRY_RUN_OK | checking file modules/ssl/ssl_engine_kernel.c; File modules/ssl/ssl_private.h is read-only; trying to patch anyway; checking file modules/ssl/ssl_private.h; Hunk #1 succeeded at 464 (offset -8 lines). |
| `CVE-2025-53020.patch` | DRY_RUN_OK | File modules/http2/h2_util.h is read-only; trying to patch anyway; checking file modules/http2/h2_util.h; File test/modules/http2/test_200_header_invalid.py is read-only; trying to patch anyway; checking file test/modules/http2/test_200_header_invalid.py |
| `CVE-2025-23048-regression.patch` | NEEDS_REVIEW | Hunk #2 FAILED at 641.; Hunk #3 succeeded at 777 (offset -18 lines).; Hunk #4 succeeded at 856 (offset -18 lines).; 1 out of 4 hunks FAILED |
| `CVE-2025-23048-regression-2.patch` | NEEDS_REVIEW | File modules/ssl/ssl_engine_kernel.c is read-only; trying to patch anyway; checking file modules/ssl/ssl_engine_kernel.c; Hunk #1 FAILED at 115.; 1 out of 1 hunk FAILED |
| `CVE-2025-58098.patch` | DRY_RUN_OK | File modules/generators/mod_cgid.c is read-only; trying to patch anyway; checking file modules/generators/mod_cgid.c; Hunk #2 succeeded at 802 (offset -1 lines). |
| `CVE-2025-65082.patch` | DRY_RUN_OK | File server/util_script.c is read-only; trying to patch anyway; checking file server/util_script.c |
| `CVE-2025-66200.patch` | DRY_RUN_OK | checking file modules/mappers/mod_userdir.c; File modules/metadata/mod_headers.c is read-only; trying to patch anyway; checking file modules/metadata/mod_headers.c; Hunk #1 succeeded at 464 (offset 9 lines). |
| `CVE-2025-55753.patch` | POSSIBLY_APPLIED | Hunk #23 succeeded at 523 (offset -174 lines).; Hunk #24 FAILED at 705.; Hunk #25 succeeded at 542 (offset -174 lines).; 17 out of 25 hunks FAILED |
| `CVE-2025-55753-3.patch` | NEEDS_REVIEW | \|+++ b/modules/md/mod_md_ocsp.c; --------------------------; No file to patch.  Skipping patch.; 1 out of 1 hunk ignored |
| `CVE-2026-23918.patch` | DRY_RUN_OK | File modules/http2/h2_mplx.c is read-only; trying to patch anyway; checking file modules/http2/h2_mplx.c |
| `CVE-2026-24072.patch` | DRY_RUN_OK | File modules/proxy/mod_proxy_fcgi.c is read-only; trying to patch anyway; checking file modules/proxy/mod_proxy_fcgi.c; Hunk #1 succeeded at 1144 (offset -130 lines).; Hunk #2 succeeded at 1179 (offset -130 lines). |
| `CVE-2026-28780.patch` | DRY_RUN_OK | File modules/proxy/ajp_msg.c is read-only; trying to patch anyway; checking file modules/proxy/ajp_msg.c |
| `CVE-2026-29168.patch` | NEEDS_REVIEW | \|+++ b/modules/md/md_ocsp.c; --------------------------; No file to patch.  Skipping patch.; 2 out of 2 hunks ignored |
| `CVE-2026-29169.patch` | DRY_RUN_OK | File modules/dav/lock/locks.c is read-only; trying to patch anyway; checking file modules/dav/lock/locks.c |
| `CVE-2026-33006-1.patch` | DRY_RUN_OK | Hunk #5 succeeded at 1426 (offset -4 lines).; Hunk #6 succeeded at 1433 (offset -4 lines).; Hunk #7 succeeded at 1783 (offset -4 lines).; Hunk #8 succeeded at 1818 (offset -4 lines). |
| `CVE-2026-33006-2.patch` | POSSIBLY_APPLIED | Hunk #3 succeeded at 385 (offset -2 lines).; File server/util.c is read-only; trying to patch anyway; checking file server/util.c; Hunk #2 succeeded at 3521 (offset -111 lines). |
| `CVE-2026-33007.patch` | DRY_RUN_OK | File modules/aaa/mod_authn_socache.c is read-only; trying to patch anyway; checking file modules/aaa/mod_authn_socache.c |
| `CVE-2026-33523.patch` | DRY_RUN_OK | File modules/http/http_filters.c is read-only; trying to patch anyway; checking file modules/http/http_filters.c; Hunk #1 succeeded at 1010 (offset -3 lines). |
| `CVE-2026-33857.patch` | DRY_RUN_OK | File modules/proxy/ajp_msg.c is read-only; trying to patch anyway; checking file modules/proxy/ajp_msg.c |
| `CVE-2026-34032.patch` | DRY_RUN_OK | File modules/proxy/ajp_msg.c is read-only; trying to patch anyway; checking file modules/proxy/ajp_msg.c |
| `CVE-2026-34059.patch` | DRY_RUN_OK | File modules/proxy/ajp_header.c is read-only; trying to patch anyway; checking file modules/proxy/ajp_header.c |
| `CVE-2026-49975.patch` | NEEDS_REVIEW | checking file modules/http2/h2_util.c; Hunk #1 succeeded at 1709 (offset 1 line).; Hunk #2 FAILED at 1721.; 1 out of 2 hunks FAILED |
| `CVE-2026-29167.patch` | DRY_RUN_OK | File modules/ldap/util_ldap.c is read-only; trying to patch anyway; checking file modules/ldap/util_ldap.c; Hunk #1 succeeded at 849 (offset -15 lines). |
| `CVE-2026-29170.patch` | DRY_RUN_OK | File modules/proxy/mod_proxy_ftp.c is read-only; trying to patch anyway; checking file modules/proxy/mod_proxy_ftp.c |
| `CVE-2026-34355.patch` | DRY_RUN_OK | File modules/filters/mod_proxy_html.c is read-only; trying to patch anyway; checking file modules/filters/mod_proxy_html.c |
| `CVE-2026-34356.patch` | DRY_RUN_OK | File modules/proxy/proxy_util.c is read-only; trying to patch anyway; checking file modules/proxy/proxy_util.c; Hunk #1 succeeded at 986 (offset -1 lines).; Hunk #2 succeeded at 1012 (offset -1 lines). |
| `CVE-2026-42535.patch` | DRY_RUN_OK | File modules/dav/fs/repos.c is read-only; trying to patch anyway; checking file modules/dav/fs/repos.c |
| `CVE-2026-42536.patch` | DRY_RUN_OK | File modules/filters/mod_xml2enc.c is read-only; trying to patch anyway; checking file modules/filters/mod_xml2enc.c |
| `CVE-2026-43951.patch` | NEEDS_REVIEW | Hunk #1 FAILED at 1386.; 1 out of 1 hunk FAILED; File modules/http2/h2_c2_filter.c is read-only; trying to patch anyway; checking file modules/http2/h2_c2_filter.c |
| `CVE-2026-44119.patch` | NEEDS_REVIEW | Hunk #3 succeeded at 1673 (offset 2 lines).; Hunk #4 succeeded at 1687 (offset 2 lines).; Hunk #5 FAILED at 1749.; 1 out of 5 hunks FAILED |
| `CVE-2026-44185.patch` | DRY_RUN_OK | File modules/ssl/ssl_util_ocsp.c is read-only; trying to patch anyway; checking file modules/ssl/ssl_util_ocsp.c; Hunk #1 succeeded at 132 (offset -1 lines). |
| `CVE-2026-44186.patch` | DRY_RUN_OK | File modules/proxy/mod_proxy_ftp.c is read-only; trying to patch anyway; checking file modules/proxy/mod_proxy_ftp.c; Hunk #1 succeeded at 1238 (offset -9 lines). |
| `CVE-2026-44631.patch` | NEEDS_REVIEW | Hunk #3 succeeded at 2585 (offset -100 lines).; File server/util_pcre.c is read-only; trying to patch anyway; checking file server/util_pcre.c; Hunk #1 succeeded at 321 (offset -5 lines). |
| `CVE-2026-48913.patch` | NEEDS_REVIEW | File modules/http2/h2_ws.h is read-only; trying to patch anyway; checking file modules/http2/h2_ws.h; File modules/http2/mod_proxy_http2.c is read-only; trying to patch anyway; checking file modules/http2/mod_proxy_http2.c |
| `CVE-2026-48913-2.patch` | DRY_RUN_OK | File modules/http2/h2_proxy_util.c is read-only; trying to patch anyway; checking file modules/http2/h2_proxy_util.c |
| `CVE-2026-56154.patch` | DRY_RUN_OK | File modules/mappers/mod_rewrite.c is read-only; trying to patch anyway; checking file modules/mappers/mod_rewrite.c; Hunk #1 succeeded at 1943 (offset 3 lines).; Hunk #2 succeeded at 1981 (offset 3 lines). |
| `CVE-2026-57941.patch` | NEEDS_REVIEW | Hunk #7 FAILED at 1732.; 1 out of 7 hunks FAILED; File modules/http2/h2_stream.h is read-only; trying to patch anyway; checking file modules/http2/h2_stream.h |
| `CVE-2026-59797.patch` | DRY_RUN_OK | File modules/ssl/ssl_engine_config.c is read-only; trying to patch anyway; checking file modules/ssl/ssl_engine_config.c; Hunk #1 succeeded at 1392 (offset -15 lines). |
| `CVE-2026-58415.patch` | NEEDS_REVIEW | Hunk #4 succeeded at 2286 (offset -40 lines).; 2 out of 4 hunks FAILED; File modules/dav/fs/repos.h is read-only; trying to patch anyway; checking file modules/dav/fs/repos.h |
| `CVE-2026-63045.patch` | DRY_RUN_OK | File modules/proxy/mod_proxy_ftp.c is read-only; trying to patch anyway; checking file modules/proxy/mod_proxy_ftp.c; Hunk #1 succeeded at 1526 (offset -11 lines).; Hunk #2 succeeded at 1566 (offset -11 lines). |
| `CVE-2026-63292.patch` | DRY_RUN_OK | File modules/mappers/mod_vhost_alias.c is read-only; trying to patch anyway; checking file modules/mappers/mod_vhost_alias.c |
| `CVE-2026-63686.patch` | DRY_RUN_OK | Hunk #1 succeeded at 521 (offset -1 lines).; Hunk #2 succeeded at 535 (offset -1 lines).; Hunk #3 succeeded at 544 (offset -1 lines).; Hunk #4 succeeded at 560 (offset -1 lines). |
| `CVE-2026-63718.patch` | DRY_RUN_OK | checking file modules/proxy/mod_proxy_uwsgi.c; Hunk #2 succeeded at 383 (offset -3 lines).; checking file test/modules/proxy/test_03_uwsgi.py; checking file test/modules/proxy/uwsgi_faker.py |
| `CVE-2026-7363X.patch` | NEEDS_REVIEW | Hunk #53 succeeded at 1840 (offset 6 lines).; Hunk #54 FAILED at 1865.; Hunk #55 succeeded at 1959 (offset 6 lines).; 11 out of 55 hunks FAILED |
| `CVE-2026-79768.patch` | DRY_RUN_OK | File modules/mappers/mod_userdir.c is read-only; trying to patch anyway; checking file modules/mappers/mod_userdir.c |
| `CVE-2026-93546.patch` | DRY_RUN_OK | Hunk #4 succeeded at 668 (offset -4 lines).; File modules/dav/main/props.c is read-only; trying to patch anyway; checking file modules/dav/main/props.c; Hunk #1 succeeded at 997 (offset -21 lines). |
| `CVE-2026-46729.patch` | DRY_RUN_OK | checking file modules/cluster/mod_heartmonitor.c; Hunk #1 succeeded at 746 (offset -1 lines).; Hunk #2 succeeded at 757 (offset -1 lines).; Hunk #3 succeeded at 789 (offset -1 lines). |
| `CVE-2026-47360.patch` | DRY_RUN_OK | File modules/session/mod_session_cookie.c is read-only; trying to patch anyway; checking file modules/session/mod_session_cookie.c; File server/util_cookies.c is read-only; trying to patch anyway; checking file server/util_cookies.c |
| `CVE-2026-56153.patch` | DRY_RUN_OK | File modules/filters/mod_charset_lite.c is read-only; trying to patch anyway; checking file modules/filters/mod_charset_lite.c |
| `CVE-2026-56449.patch` | DRY_RUN_OK | File modules/filters/mod_proxy_html.c is read-only; trying to patch anyway; checking file modules/filters/mod_proxy_html.c; Hunk #1 succeeded at 332 (offset 23 lines). |
| `CVE-2026-106023.patch` | NEEDS_REVIEW | 1 out of 1 hunk FAILED; File modules/md/mod_md_status.c is read-only; trying to patch anyway; checking file modules/md/mod_md_status.c; Hunk #1 succeeded at 72 (offset -5 lines). |
| `CVE-2026-109163.patch` | NEEDS_REVIEW | File modules/mappers/mod_vhost_alias.c is read-only; trying to patch anyway; checking file modules/mappers/mod_vhost_alias.c; Hunk #1 FAILED at 244.; 1 out of 1 hunk FAILED |
| `CVE-2026-119618.patch` | DRY_RUN_OK | File modules/http2/h2_request.c is read-only; trying to patch anyway; checking file modules/http2/h2_request.c; Hunk #1 succeeded at 345 (offset -5 lines). |
| `CVE-2026-42528.patch` | DRY_RUN_OK | File modules/dav/main/util.c is read-only; trying to patch anyway; checking file modules/dav/main/util.c; Hunk #1 succeeded at 939 (offset -55 lines).; Hunk #2 succeeded at 951 (offset -55 lines). |
