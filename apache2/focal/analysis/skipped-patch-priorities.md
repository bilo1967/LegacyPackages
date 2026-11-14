# Apache Focal: triage of 10 skipped Jammy patches

Status: experimental only. Reviewed against `experimental-manifest.md` and
`skipped-patch-diagnostics.md` on branch `backport/focal`.

**A passing build or smoke test does not imply that a skipped CVE is fixed.**
Keep the current fail-closed `patch --fuzz=0` policy. Do not apply partial
multi-hunk patches or alter Apache's module magic number without an ABI review.

| Patch | Priority for investigation | Blocker / scope | Next action |
|---|---|---|---|
| `CVE-2026-7363X.patch` | High | `mod_auth_digest.c`; 9 of 55 hunks fail against Focal | Port and review all security-relevant hunks as one coherent change; test Digest auth and regressions. If the module is unnecessary in a deployment, independently assess disabling it. |
| `CVE-2025-55753.patch` | High | Major `mod_md` codebase mismatch; 17 of 25 hunks fail (manifest summary); broad ACME/OCSP changes | First map the affected features to Focal's `mod_md`, then determine whether a complete, auditable backport or a supported module update is viable. |
| `CVE-2025-55753-3.patch` | Dependent | Follow-up to previous `mod_md` patch; missing `mod_md_ocsp.c` | Do not import independently; revisit only with the complete prerequisite series. |
| `CVE-2026-29168.patch` | Dependent | References missing `modules/md/md_ocsp.c` | Determine whether the affected OCSP implementation exists in Focal under a different architecture before deciding applicability. |
| `CVE-2026-43951.patch` | High | Combined HTTP/1.1 serializer and HTTP/2 patch; `h2_c2_filter.c` absent; HTTP/1.1 hunk fails with zero fuzz | Inspect the separate `http_filters.c` behavior after CVE-2024-42516. Do not label the full CVE fixed from only a partial hunk. |
| `CVE-2026-48913.patch` | High | Extensive HTTP/2 refactor; numerous source-layout mismatches and missing `mod_proxy_http2.c` | Compare installed Focal HTTP/2 module packaging and features before judging exposure; no partial backport. |
| `fix-a-possible-listener-deadlock.patch` | Medium | `event.c` MPM behavior differs; 4/6 hunks fail | Requires event MPM lifecycle review and stress testing (graceful restart, worker saturation). |
| `handle-children-killed-pathologically.patch` | Medium | Event/worker MPM restart heuristics differ; first hunk fails in each file | Review process-recovery logic and test repeated failed child handling, without production tests. |
| `mod_proxy_hcheck_jammy_fix_to_detect_support.patch` | Medium | Jammy-only optional AJP detection code/context and an extraneous patch-named file hunk | Compare optional AJP hooks and health-check method initialization on Focal. |
| `reenable-workers-in-standard-error-state-jammy-apache2.patch` | Medium, ABI-sensitive | Changes proxy header and Jammy module magic minor version; Focal differs | Evaluate source and binary compatibility of Focal proxy/health-check modules before changing public headers or module magic. |

## Recommended order

1. **Security-critical code review**: Digest auth (`CVE-2026-7363X`),
   `mod_md` (`CVE-2025-55753` and prerequisites), and the HTTP
   serializer portion of `CVE-2026-43951`.
2. **Determine actual Focal HTTP/2 and `mod_md` feature exposure** before
   claiming that patches targeting missing source files are not applicable.
   A missing path in the Apache source tree alone is not proof of safety:
   Ubuntu may ship a module from a separate source package.
3. **MPM/proxy patch group** only after compatibility and restart/health-check
   tests exist; protect compatibility with existing binary modules.

## Invariants

- Preserve the 57 applied / 10 skipped count until a complete patch is
  demonstrably applicable, reviewable and passes all disposable CI.
- Record Focal-specific adaptations as standalone quilt patches or exact
  patch transformations, never silent source edits.
- Do not deploy to `gojira`.
