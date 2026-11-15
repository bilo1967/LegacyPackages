# Apache 2.4.29 for Ubuntu 18.04 (Bionic) - RC1

**Debian version:** `2.4.29-1ubuntu4.27+bilo1~rc1` (amd64).

Independent selective Apache security backport, retaining Ubuntu 18.04 packaging and module ABI. **Not equivalent to Canonical ESM, and not a complete fix for all outstanding vulnerabilities.**

## Security fixes

| CVE | Integration |
| --- | --- |
| CVE-2026-63292 | Original Jammy security patch |
| CVE-2026-56153 | Original Jammy security patch |
| CVE-2026-56154 | Native Bionic adaptation for mod_rewrite LA-U/LA-F lookahead |
| CVE-2026-44119 | Native Bionic adaptation for restricted file-expression evaluation |
| CVE-2026-59797 | Native Bionic mod_ssl SSLRequire fix requiring the preceding parser fix |

Other issues, including older vulnerabilities and fixes for modules not loaded on mrscoulter, remain for subsequent work.

## Contents and validation

The package set contains only five Apache DEBs: `apache2`, `apache2-bin`, `apache2-data`, `apache2-utils`, `apache2-dev`. The archive `apache2-bionic-rc1-packages.tar.gz` preserves the original Debian filenames (`+` and `~` may be normalized by GitHub for individual release attachments). `SHA256SUMS` and `PATCH-MANIFEST.md` are included. No PHP package is distributed.

[GitHub Actions successful build and upgrade test](https://github.com/bilo1967/LegacyPackages/actions/runs/43718996495): install simulation upgraded only the five Apache packages; Apache, SSL, rewrite, HTTP and prefork passed smoke tests. PHP 7.4.33 from Niek remained unchanged, and its `libapache2-mod-php7.4` served PHP via `apache2handler`. The maintainer installed the RC on mrscoulter and reported successful functional checks (15 November 2026). No full security audit was performed.

## Installation and rollback

Before upgrading, back up `/etc/apache2` and keep the original Ubuntu `2.4.29-1ubuntu4.27` DEBs. Extract the RC tar archive into an empty directory and run:

```sh
sha256sum -c SHA256SUMS
apt -s install ./*.deb
```

Proceed only if APT proposes changes to **exactly the five Apache packages**, with no changes to PHP. Then:

```sh
apt install ./*.deb
apache2ctl configtest
systemctl status apache2
apache2ctl -M
```

Package scripts can restart Apache automatically. Verify production virtual hosts. For rollback, reinstall the five original Ubuntu Apache packages together, restoring saved configuration if needed.

## References

- [Exact tested source revision](https://github.com/bilo1967/LegacyPackages/commit/1cc1f4c2bfc05b2576801cd4bb0e3210a11be56f)
- [Build and validation run](https://github.com/bilo1967/LegacyPackages/actions/runs/43718996495)
- [Detailed Bionic project notes](https://github.com/bilo1967/LegacyPackages/blob/backport/bionic/apache2/bionic/README.md)
- [Deferred CVE inventory](https://github.com/bilo1967/LegacyPackages/blob/backport/bionic/apache2/bionic/priority-2026-11.md)

No institutional endorsement is implied.
