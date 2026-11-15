# Apache 2.4.29 for Ubuntu 18.04 (Bionic) - RC1

**Debian version:** `2.4.29-1ubuntu4.27+bilo1~rc1`. **Platform:** amd64.

Selective interim security backport for Ubuntu Bionic, preserving standard Apache packaging and module ABI. Fixes: CVE-2026-63292, CVE-2026-56153, CVE-2026-56154, CVE-2026-44119, CVE-2026-59797. This **does not** replace Canonical ESM or cover every outstanding vulnerability.

Five Apache DEBs are provided, with SHA256 checksums and an archive retaining the exact Debian filenames. PHP packages are not included.

[Successful CI build and APT/PHP compatibility tests](https://github.com/bilo1967/LegacyPackages/actions/runs/43718996495). No PHP package changes or rebuild were needed; the maintainer installed the packages on mrscoulter and reports normal operation.

For installation and rollback instructions, see the attached README.md or [online documentation](https://github.com/bilo1967/LegacyPackages/blob/backport/bionic/apache2/bionic/RC1-README.md).
