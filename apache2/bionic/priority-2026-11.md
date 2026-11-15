# Apache 2.4 security triage for Ubuntu 18.04 Bionic — mrscoulter

**Status (2026-11-15): selection and source applicability only; no patch has been applied, no package has been compiled, no production changes.**

This is an intentionally **narrow interim security backport**, not a rerun of the Focal 63-patch program. Baseline package family: `2.4.29-1ubuntu4.27`, **but actual installed revision on mrscoulter must be checked** before making any vulnerability claims. Canonical's complete patched Bionic ESM reference is `2.4.29-1ubuntu4.27+esm15` (USN-9090-1). The exact ESM source is preferable if access is available.

## Phase 1 — selected recent vulnerabilities

Priority is a combination of **impact** and **actual exposure**, not just publication date or CVE count. A code-level port is proposed only if the vulnerable path actually exists in Bionic and has not already been fixed.

| CVE | Canonical notice | Potential impact | Component / triage |
| --- | --- | --- | --- |
| CVE-2026-109163 | USN-9090-1, 12 Nov | Stack overflow; potential RCE / DoS | `mod_vhost_alias`; check if installed/loaded; select for source review. |
| CVE-2026-56153 | USN-9016-1, 10 Nov | Memory fault; potential RCE / DoS | Core/path to identify from upstream patch; select. |
| CVE-2026-63292 | USN-8931-1, 14 Oct | Potential RCE / DoS | HTTP request handling; select. |
| CVE-2026-56154 | USN-8898-1, 7 Oct | Potential RCE / DoS | `mod_rewrite`; select; frequently loaded. |
| CVE-2026-59797 | USN-8898-1, 7 Oct | Access-control bypass | `mod_ssl` expression handling; select. |
| CVE-2026-47360 | USN-9016-1, 10 Nov | Session cookie information disclosure | Session handling; select. |
| CVE-2026-46729 | USN-9016-1, 10 Nov | Denial of service | Memory handling; check code path. |
| CVE-2026-48005 | USN-9016-1, 10 Nov | Unauthenticated DoS | Authentication; check path. |

**Conditional additions based on enabled features, not automatic imports:**

- `CVE-2026-57941` (USN-8898-1): `mod_http2` memory corruption, possible RCE. Include immediately if HTTP/2 is installed and exposed.
- `CVE-2026-73636` (USN-8931-1): Digest authentication bypass under MITM circumstances. Include if Digest is used; this may entail regression/prerequisite patches.
- `CVE-2026-42528` (USN-9090-1): `mod_dav` locking DoS; review if WebDAV/locking is enabled.
- `CVE-2026-63045` (USN-8931-1): forward-proxy FTP backend response issue; review if FTP forwarding is possible.

**Explicitly not in the immediate Bionic tranche:** `CVE-2026-106023` (`mod_md`), `CVE-2026-119618` (`mod_http2` new-header fault), `CVE-2026-56449`, and `CVE-2026-63718`, because the cited Ubuntu notices explicitly exclude Bionic. Do **not** import the similarly named Jammy patch simply because it exists in the Focal manifest.

The remaining October and earlier CVEs are not presumed safe. Defer them to phase 2; give particular attention to the July configuration-expression issue `CVE-2026-44631` (possible code execution/DoS on Bionic), and to `CVE-2026-44185` (`mod_ssl` OCSP) if exposed.

## Efficient execution plan (strict time and GitHub Actions budget)

1. Read-only inventory of mrscoulter, *before* selecting patches:
   ```sh
   apache2 -v
   apt-cache policy apache2 apache2-bin apache2-dev
   apache2ctl -M
   dpkg-query -W 'apache2*' 'libapache2-mod-*' 2>/dev/null
   ```
   Identify use of `mod_ssl`, `mod_rewrite`, HTTP/2, `mod_dav`, `mod_vhost_alias`, Digest, and backend proxy protocols; confirm external Apache DSOs and PHP handler. Do not publish sensitive vhost definitions.
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

**Safety:** exposure and installed patch level are presently unverified for mrscoulter. The fact that an old bug has not visibly been exploited is no evidence that it is safe; the interim shortlist leaves a known residual security gap by design.
