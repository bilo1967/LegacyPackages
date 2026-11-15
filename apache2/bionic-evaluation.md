# Ubuntu 18.04 Bionic: Apache security decision (15 November 2026)

**Decision: do not start a full Bionic backport now.** This document records why, so that a future maintainer can make a focused choice without repeating the Focal investigation.

## Exposure: yes, Bionic still receives relevant advisories

Ubuntu 18.04 ships Apache **2.4.29**. Its current official patched line is distributed via Ubuntu Pro/ESM. [USN-9090-1 (12 November 2026)](https://ubuntu.com/security/notices/USN-9090-1) names **`2.4.29-1ubuntu4.27+esm15`** for Bionic.

The notice applies to Bionic and, among others, includes `CVE-2026-42528` (`mod_dav`) and `CVE-2026-109163` (`mod_vhost_alias`). The same notice explicitly lists `CVE-2026-106023` (`mod_md`) and `CVE-2026-119618` (`mod_http2`) as affecting newer supported releases **but not 18.04**. Other Bionic-specific exposure remains: for example [USN-8898-1](https://ubuntu.com/security/notices/USN-8898-1), [USN-8931-1](https://ubuntu.com/security/notices/USN-8931-1), [USN-9016-1](https://ubuntu.com/security/notices/USN-9016-1), and [USN-8338-1](https://ubuntu.com/security/notices/USN-8338-1) include 18.04.

Thus the answer is **not** “these recent bugs do not affect 18.04.” It is that actual applicability varies **per CVE, version, module, and patched-package status**.

## Can Focal work be reused?

- **Mostly reusable:** Docker GitHub Actions architecture, source provenance tracking, exact `apt-get source` and `dpkg-buildpackage` pattern, quilt zero-fuzz import algorithm, manifest of applied/skipped diffs, isolated smoke tests, PHP-FPM/proxy/SSL test approach, CI publication race checks, regression-test scripts where code contracts match.
- **Not automatically reusable:** Focal-native hunks, 2.4.41-only API workarounds, MPM or HTTP/2 implementations, mod_md architecture and OCSP assumptions, distro-specific patch series and package dependencies, third-party DSO ABI compatibility. Bionic source is 2.4.29; even if code is conceptually similar, context differs.
- **Current repository state:** only `apache2/focal/` has a working package stream. No `apache2/bionic/` build, Bionic source manifest, or validated candidate exists. A prior mention of a Bionic workstream in the old root README was just a plan.

A full 63-patch transplantation to Bionic has **unknown duration** and is likely to reproduce a substantial amount of compatibility work. Do not assume Focal success implies a quick Bionic release.

## Recommended order of operations

1. **Check actual host exposure first**: `apache2 -v`, `apt-cache policy apache2`, `apache2ctl -M`, public-facing vhost/use of WebDAV, vhost alias, HTTP/2, reverse proxies, CGI, `mod_md`, third-party Apache DSOs. Inspect only what is needed; do not publish private configuration.
2. If the host can receive **Ubuntu Pro/ESM** updates, prefer official `apache2` packages to a new backport. Also review broader 18.04 platform/dependency security, not just Apache.
3. If Pro is unavailable, **prefer an OS upgrade or a Caddy migration** when the application stack is straightforward. Caddy serves modern sites with PHP-FPM using [`php_fastcgi`](https://caddyserver.com/docs/caddyfile/directives/php_fastcgi) and supports proxy/WebSocket services through [`reverse_proxy`](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).
4. A Caddy migration is **not** a drop-in replacement if the host depends on `mod_php`, `.htaccess`, `mod_fcgid`, Apache-specific authentication/rewrites or custom modules. Budget for reworking PHP handlers, application routing and vhosts; replace `mod_php` with PHP-FPM and verify legacy code compatibility. Replacing Apache alone does not secure an otherwise obsolete OS.
5. Consider a **selective** Bionic patch port only if a small number of still-relevant CVEs remain, source files exist in Bionic, matching security patches apply with minimal rebase, and the existing CI can provide sufficient tests. Stop quickly if the exact patch-series diff reveals another large multi-module port.

**Practical default:** no Bionic patch-development work. Apply official ESM, modernize the OS or migrate the service; only a short targeted dry-run could justify revisiting this decision.

Sources: [USN-9090-1](https://ubuntu.com/security/notices/USN-9090-1), [USN-9016-1](https://ubuntu.com/security/notices/USN-9016-1), [USN-8898-1](https://ubuntu.com/security/notices/USN-8898-1), [USN-8338-1](https://ubuntu.com/security/notices/USN-8338-1). Security situation and exact installed versions should be rechecked before any future deployment.
