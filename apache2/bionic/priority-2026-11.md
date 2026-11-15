# Apache 2.4 security triage for Ubuntu 18.04 Bionic — mrscoulter

**Status (2026-11-15): selection and source applicability only; no patch has been applied, no package has been compiled, no production changes.**

This is an intentionally **narrow interim security backport**, not a rerun of the Focal 63-patch program. Installed and confirmed on mrscoulter: `apache2`, `apache2-bin`, `apache2-data`, `apache2-utils`, and `apache2-dev` at exactly `2.4.29-1ubuntu4.27` (2026-11-15). Canonical's complete patched Bionic ESM reference is `2.4.29-1ubuntu4.27+esm15` (USN-9090-1). The exact ESM source is preferable if access is available.

## Verified host inventory (15 November 2026)

- **Apache:** 2.4.29, Ubuntu package `2.4.29-1ubuntu4.27`, MPM **prefork**.
- **Loaded:** `ssl`, `rewrite`, `proxy`, `proxy_http`, `cgi`, `include`, `headers`, `auth_basic`, `authn_file`, `authz_core`, `php7_module`, plus ordinary core/utility modules.
- **Not loaded:** `http2`, `md`, `dav`, `dav_fs`, `vhost_alias`, `auth_digest`, `proxy_ftp`, `proxy_fcgi`, `fcgid`, `jk`, `php7.2` and any PHP 5 module. Do not claim those optional components cannot be enabled in the future.
- **PHP:** actual active integration is mod_php 7.4.33 from Niek's Bionic package (`libapache2-mod-php7.4`). PHP 7.4 FPM also installed, but no `proxy_fcgi` is loaded. PHP below 7.4 is out of scope; remove legacy packages only after checking dpkg *installed* state and doing an APT purge simulation.
- Warnings about `ScriptAlias` overlap and absent document roots predate this project and do not block source patch triage.
- `dpkg-query -W` without the Status column can also display uninstalled package records; do **not** infer that all `apache2*` and `libapache2-mod-*` names in its output are installed.

## Phase 1 — source shortlist for mrscoulter

Prioritize known relevant **code paths** and remote impact; a patch is admitted only after comparison against Bionic 2.4.29. This is a planning list, **not** a list of fixed vulnerabilities.

| CVE | Notice | Impact and host priority |
| --- | --- | --- |
| **CVE-2026-56153** | USN-9016-1, 10 Nov | Possible code execution/DoS in memory handling; **high — core review**. |
| **CVE-2026-63292** | USN-8931-1, 14 Oct | Possible code execution/DoS handling HTTP requests; **high — HTTP code review**. |
| **CVE-2026-56154** | USN-8898-1, 7 Oct | Possible code execution/DoS in **loaded `mod_rewrite`**; **high**. |
| **CVE-2026-59797** | USN-8898-1, 7 Oct | Potential access-control bypass in **loaded `mod_ssl`**; **high** (actual affected configuration to check). |
| **CVE-2026-46729** | USN-9016-1, 10 Nov | Memory-handling DoS; **include in source review**. |
| **CVE-2026-48005** | USN-9016-1, 10 Nov | Unauthenticated DoS in authentication processing; **include in source review**. |
| **CVE-2026-47360** | USN-9016-1, 10 Nov | Cookie-information disclosure; **include if the vulnerable session logic is present/reachable**. |
| **CVE-2026-63686** | USN-8931-1, 14 Oct | DoS in processing backend responses; **include in source review** because `proxy_http` is loaded. |
| **CVE-2026-73637** | USN-8931-1, 14 Oct | Authentication-processing DoS; **include if source path matches**. |

**Deferred pending actual module/feature use** (not proven fixed): `CVE-2026-42528` (`mod_dav`), `CVE-2026-109163` (`mod_vhost_alias`, possible code execution), `CVE-2026-57941` (`mod_http2`), `CVE-2026-73636` (`mod_auth_digest`), `CVE-2026-58415`/`CVE-2026-93546` (WebDAV), `CVE-2026-63045` (FTP forward-proxy), `CVE-2026-79768` (user-directory restrictions; assess if userdir is actually active). `CVE-2026-109163` is **serious**, but its module is *not loaded* on this host; if enabled elsewhere, reprioritize immediately.

**Not applicable to Bionic per Canonical notices:** `CVE-2026-106023` (newer `mod_md`), `CVE-2026-119618` (newer HTTP/2 path), `CVE-2026-56449`, `CVE-2026-63718`. Do not blindly copy those Jammy patch files. July and earlier issues remain a separate backlog, not a clean security bill.

## Efficient execution plan (strict time and GitHub Actions budget)

1. **Inventory completed**: exact base packages, active modules and PHP integration confirmed above. If cleaning up legacy PHP, use dpkg Status-Abbrev to distinguish installed packages from historical records; simulate purges before proceeding.
2. Reuse the **method**, not the resulting Focal binaries: retrieve official Bionic source `2.4.29-1ubuntu4.27` and existing Jammy candidate patch files; run **local/source-only zero-fuzz dry runs** against just the selected patches. Review genuine C path/context and prerequisite/regression fix relationships. Record applicability in a manifest. Do not infer effectiveness from clean application alone.
3. If the selected fixes have manageable context, perform **one** Docker Ubuntu 18.04 build with a custom Debian version and test the modules actually used by mrscoulter, including ABI preservation and PHP. Start with only the narrow patch set; do not automatically add the remaining 50+ Jammy changes.
4. Do not run the full Focal CI matrix. Limit CI to one build and one operational smoke test; stop if source/API incompatibilities multiply. The current free GitHub Actions minutes are nearly exhausted, so prefer a local disposable container (or a runner with available budget), not repeated cloud experiments.
5. Keep the output labeled **INTERIM / PARTIAL SECURITY BACKPORT**; never describe it as ESM-equivalent or fully patched. It must not silently replace the host's PHP, `mod_php`, custom DSOs or configs.

## Source references

- [USN-9090-1](https://ubuntu.com/security/notices/USN-9090-1) (12 Nov 2026): Bionic `+esm15`.
- [USN-9016-1](https://ubuntu.com/security/notices/USN-9016-1) (10 Nov 2026): Bionic `+esm14`.
- [USN-8931-1](https://ubuntu.com/security/notices/USN-8931-1) (14 Oct 2026): Bionic `+esm13`.
- [USN-8898-1](https://ubuntu.com/security/notices/USN-8898-1) (7 Oct 2026).
- [USN-8571-1](https://ubuntu.com/security/notices/USN-8571-1) (20 Jul 2026): earlier candidate tranche, intentionally deferred.
- [Focal backport technical record](https://github.com/bilo1967/LegacyPackages/blob/backport/focal/apache2/focal/README.md).

**Safety:** installed Apache version and loaded modules are known; **CVE path-level exposure remains to be established against source**. The fact that an old bug has not visibly been exploited is no evidence that it is safe; the interim shortlist leaves a known residual security gap by design.

## Interim implementation checkpoint — 15 Nov 2026

- [Dry-run source applicability report](analysis/selected-patch-audit.md):
  **2 clean**, **3 accepted with offsets** needing manual inspection,
  **3 failing** and needing source adaptation.
- [Successful source compilation](https://github.com/bilo1967/LegacyPackages/actions/runs/43711158241)
  with **only CVE-2026-63292 and CVE-2026-56153**. The job built the DEBs;
  an initial CI smoke-test omitted the `wget` dependency.
- [Separate successful smoke test](https://github.com/bilo1967/LegacyPackages/actions/runs/43711428472)
  reused the same package files to test install, MPM prefork and HTTP.
- **Remaining priority:** inspect offsets for `CVE-2026-59797`,
  `CVE-2026-46729`, `CVE-2026-47360`; port `CVE-2026-56154`
  and `CVE-2026-63686`. Review the conditional `CVE-2026-7363X`
  path against Bionic auth code and mrscoulter's active auth modules.
  Verify binary compatibility with Niek's installed mod_php 7.4.33
  before considering any host installation.

## Five-fix experimental package and PHP validation

A selective source backport now incorporates `CVE-2026-63292`, `CVE-2026-56153`, `CVE-2026-56154`, `CVE-2026-44119` and `CVE-2026-59797`. The expression-parser port for `44119` is an upstream dependency of the SSLRequire fix for `59797`.

- [Package build and Apache runtime smoke test: success](https://github.com/bilo1967/LegacyPackages/actions/runs/43712616135).
- [Compatibility smoke test with Niek's Bionic PHP 7.4.33: success](https://github.com/bilo1967/LegacyPackages/actions/runs/43713119730).
- Experimental package version: `2.4.29-1ubuntu4.27+bilo0~experimental2`; no production deployment.
- `mod_heartmonitor`, `mod_session_cookie` and `mod_xml2enc` are not loaded on mrscoulter: defer their patches from the initial host-specific batch. Other older vulnerabilities still require later assessment.
