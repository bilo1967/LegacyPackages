# Focal ESM backport milestones (as of 2026-11-14)

Target: reproduce *applicable* Apache 2.4.41 security corrections from Ubuntu's last public Focal source `2.4.41-4ubuntu3.23` through ESM `+esm11`, without changing Debian packaging semantics.

| Ubuntu Pro version | Security notice | Relevant notes |
| --- | --- | --- |
| +esm1 | UNRESOLVED | Needs provenance; do not assume no content. |
| +esm2 | [USN-7639-2](https://ubuntu.com/security/notices/USN-7639-2) | July 2025 CVEs delivered on Focal in August 2025. |
| +esm3 | [USN-8338-1](https://ubuntu.com/security/notices/USN-8338-1) | May 2026. |
| +esm4 | [USN-8396-1](https://ubuntu.com/security/notices/USN-8396-1) | June 2026. |
| +esm5 | [USN-8571-1](https://ubuntu.com/security/notices/USN-8571-1) | July 2026. |
| +esm6 | [USN-8589-1](https://ubuntu.com/security/notices/USN-8589-1) | July 2026. |
| +esm7 | [USN-8571-2](https://ubuntu.com/security/notices/USN-8571-2) | Regression repair, must be retained. |
| +esm8 | [USN-8898-1](https://ubuntu.com/security/notices/USN-8898-1) | October 2026. |
| +esm9 | [USN-8931-1](https://ubuntu.com/security/notices/USN-8931-1) | October 2026. |
| +esm10 | [USN-9016-1](https://ubuntu.com/security/notices/USN-9016-1) | November 2026. |
| +esm11 | [USN-9090-1](https://ubuntu.com/security/notices/USN-9090-1) | November 2026. |

## Provenance and gating

- ESM binary and source repository access is authenticated through Ubuntu Pro: https://documentation.ubuntu.com/security/security-updates/esm/ . Do not assume the exact ESM source is publicly downloadable.
- Public Jammy patch inventory provides **candidates** only. Source version 2.4.52 is not directly interchangeable with Focal 2.4.41.
- Focal production uses prefork, mod_php7, fcgid, maxminddb, rewrite, ssl and multiple proxy modules; preserve the module ABI and do not change its MPM.
- The initial baseline GitHub Actions build and operator Docker build both completed, with similar package sizes. This **does not** establish reproducible byte-identical packages.
- **No CVE is currently claimed fixed in our build.** No custom source or deployment package is released.

## CI additions

[compare workflow](../../../.github/workflows/apache2-focal-compare.yml) and [patch series comparator](tools/compare-patches.py): retrieve official public Focal and Jammy source and upload a candidate patch series diff. This report is exploratory only; it does not prove completeness.

Next deliverable: examine its artifact and extract individual patch sets with known upstream commit provenance, adapt to 2.4.41, apply quilt series with integration tests, increment changelog with private custom version.
