# Bionic selected Apache CVE patch source audit

Generated: 2026-11-15T11:49:08.495277+00:00
Baseline: Bionic source 2.4.29-1ubuntu4.27; candidates from Jammy 2.4.52-1ubuntu4.27.

**Read-only dry-run only.** No patch applied, no package built, no claim of remediation.
Each candidate is checked independently. Dependency or regression patches may be required.
Zero fuzz is used. Offsets still require manual review.

| Patch | Target | Result | Detail |
|---|---|---|---|
| `CVE-2026-56154.patch` | mod_rewrite / Oct 7 | **needs-port** | exit 1, failed/malformed markers: 1 |
| `CVE-2026-59797.patch` | mod_ssl / Oct 7 | **dry-run-offset** | All hunks accepted; offset count: 1 |
| `CVE-2026-63292.patch` | HTTP handling / Oct 14 | **dry-run-clean** | All hunks accepted; offset count: 0 |
| `CVE-2026-63686.patch` | proxy/backend responses / Oct 14 | **needs-port** | exit 1, failed/malformed markers: 1 |
| `CVE-2026-7363X.patch` | auth (shared 73636/73637) / Oct 14: conditional | **needs-port** | exit 1, failed/malformed markers: 11 |
| `CVE-2026-46729.patch` | memory handling / Nov 10 | **dry-run-offset** | All hunks accepted; offset count: 3 |
| `CVE-2026-47360.patch` | sessions / Nov 10 | **dry-run-offset** | All hunks accepted; offset count: 1 |
| `CVE-2026-56153.patch` | memory handling / Nov 10 | **dry-run-clean** | All hunks accepted; offset count: 0 |

## Excluded from this initial code audit

- CVE-2026-109163: mod_vhost_alias absent from mrscoulter loaded modules; serious but deferred for host exposure.
- CVE-2026-48005: mod_auth_digest is not loaded; do not treat a shared Digest patch as mandatory for this host.
- CVE-2026-57941: mod_http2 not loaded.
- CVE-2026-42528: mod_dav not loaded.

## Next
Review failed hunks against Bionic source, cross-check whether the CVE is
actually in the installed version, and port only the necessary security
change plus prerequisites. After that, build and test in a disposable
Ubuntu 18.04 container preserving external module ABI.
