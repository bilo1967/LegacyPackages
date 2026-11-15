# Apache 2.4 Bionic — narrow security backport

**Phase:** source and exposure triage only; **no** Bionic patched binaries available yet.

Target: `mrscoulter` (Ubuntu 18.04 / Apache 2.4.29). Installed package revision confirmed on 2026-11-15: `2.4.29-1ubuntu4.27`; loaded modules and PHP integration inventoried. This branch is intentionally independent of the completed Focal RC.

The project prioritizes the high-impact CVEs disclosed on **7 October, 14 October, 10 November and 12 November 2026**, rather than importing the entire 63-patch Focal/Jammy candidate inventory.

Read the [focused CVE shortlist and time-limited build strategy](priority-2026-11.md). Priority now includes core/HTTP handling, loaded `mod_rewrite`, `mod_ssl`, `proxy_http`, and authentication; optional un-loaded modules are deferred. Only patches affecting the actual Bionic source and relevant server features should proceed into an interim package. The final Canonical ESM reference is `apache2 2.4.29-1ubuntu4.27+esm15` (USN-9090-1).

**Constraints:** preserve Bionic's binary module ABI and existing Apache/PHP integrations; never transplant Focal or Jammy binaries. Use a disposable Bionic build container; minimal CI runs; verify installed modules before choosing optional CVEs. A partial backport is not equivalent to Ubuntu Pro/ESM.

## First source audit and experimental proof of packaging (15 November 2026)

The [selected-CVE dry-run report](analysis/selected-patch-audit.md) checked eight
Jammy source patches against Ubuntu Bionic `2.4.29-1ubuntu4.27`. Results:
two zero-offset clean patches (`CVE-2026-63292`, `CVE-2026-56153`),
three hunks accepted with offsets (require manual context review), and three
patches requiring adaptation. Passing a patch dry-run does **not** prove
security remediation.

An **experimental two-CVE package set** was successfully compiled as
`2.4.29-1ubuntu4.27+unibo0~experimental1` during
[CI run #5](https://github.com/bilo1967/LegacyPackages/actions/runs/43711158241).
The original full workflow is marked failed solely because its smoke-test
container omitted the `wget` test tool. Its binary-build stage succeeded;
the package artifact is attached to that CI run.

The [independent smoke test](https://github.com/bilo1967/LegacyPackages/actions/runs/43711428472)
reused those exact DEBs **without rebuilding** and succeeded: package
installation, prefork MPM, selected SSL/rewrite/proxy/CGI modules, Apache
configuration and actual HTTP response were checked in a fresh Ubuntu 18.04
container.

**Do not install this proof-of-concept on mrscoulter yet.** It does not include
all high-priority fixes, and the host's Niek PHP 7.4.33 binary module has
not yet been tested against these packages. PHP must not be upgraded or
reinstalled as a side effect of the Apache security backport.
