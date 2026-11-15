# Apache 2.4.41 security backport for Ubuntu 20.04 (Focal) — RC1

**Pre-release, suitable for controlled testing.** Debian version: `2.4.41-4ubuntu3.23+unibo1~rc1` (amd64 and architecture-independent package data).

This build aims to replace Ubuntu Focal's `apache2 2.4.41-4ubuntu3.23` while retaining packaging, existing `/etc/apache2` conffiles and external module ABI. **It does not package, reinstall or upgrade PHP.** The maintainer tested installation on a Focal server and reported the existing Apache/PHP services working.

## Security patches and scope

63 patch files were imported and adapted from the Ubuntu Jammy `apache2 2.4.52-1ubuntu4.27` patch series. Four Jammy patch files were excluded:

- `CVE-2025-55753.patch`: newer `mod_md` implementation; the vulnerable Focal-native ACME backoff calculation was fixed separately and checked with UBSan.
- `CVE-2025-55753-3.patch`: newer `MDStapleOthers` regression fix, not present in Focal `mod_md`.
- `CVE-2026-29168.patch`: newer `md_ocsp.c` code is absent in Focal (independent `mod_ssl` OCSP is not addressed by this finding).
- `mod_proxy_hcheck_jammy_fix_to_detect_support.patch`: newer AJP hook-detection logic does not exist in the same form in Focal.

The patch import is **not** a verified source-equivalent substitute for Canonical's Ubuntu Pro/ESM updates. Review the [technical README](https://github.com/bilo1967/LegacyPackages/blob/backport/focal/apache2/focal/README.md), [CVE-2025-55753 findings](https://github.com/bilo1967/LegacyPackages/blob/backport/focal/apache2/focal/analysis/cve-2025-55753-focal.md) and the attached `PATCH-MANIFEST.md`.

## Package installation and rollback

The release contains only these five Apache binary packages:

- `apache2`
- `apache2-bin`
- `apache2-data`
- `apache2-utils`
- `apache2-dev` (only required if the development package is installed or needed)

From a directory containing only the five Apache `.deb` files:

```sh
apt -s install ./*.deb
apt install ./*.deb
apache2ctl configtest
systemctl status apache2
```

Confirm the APT transaction involves only Apache before installation. Debian conffiles under `/etc/apache2` are normally retained; save a backup and check any conffile prompts. Packaging scripts may restart Apache.

For rollback, retain copies of the original Ubuntu `2.4.41-4ubuntu3.23` DEBs or ensure that exact version remains available in APT sources. Downgrade all installed Apache packages to the same version together.

## Build and validation

The full RC build/test job succeeded in [GitHub Actions RC run #1](https://github.com/bilo1967/LegacyPackages/actions/runs/43698324239). That overall run failed only in its subsequent release-upload phase. The existing validated build artifact is reused without recompilation.

The disposable Focal test suite covers prefork/event/worker MPMs, SSL/rewrite, proxy HTTP/FCGI/WebSocket, mod_fcgid, mod_auth_digest, mod_md load, mod_php 7.4/8.3/8.4, PHP-FPM 8.3/8.4 and a UBSan regression test for the native ACME retry backoff. PHP packages were **test inputs only** and are not distributed in this release.

The attached `SHA256SUMS` verifies the binary files. No claim of a comprehensive ESM security equivalence test is made.
