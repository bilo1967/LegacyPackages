# Apache 2.4.29 for Ubuntu 18.04 (Bionic) — interim RC1

**Version**: `2.4.29-1ubuntu4.27+bilo1~rc1` (amd64).

**Scope**: selective interim backport for `mrscoulter`, based on the stock Ubuntu Bionic `apache2 2.4.29-1ubuntu4.27` source package, preserving Ubuntu packaging and the Apache module ABI. This is **not** an Ubuntu Pro/ESM replacement and **not** a complete fix for all outstanding CVEs.

Included upstream-security patch entries:

- `CVE-2026-63292`: Jammy patch applied unchanged;
- `CVE-2026-56153`: Jammy patch applied unchanged;
- `CVE-2026-56154`: reviewed native Bionic port, `mod_rewrite`;
- `CVE-2026-44119`: reviewed Bionic port of restricted file-expression parser;
- `CVE-2026-59797`: reviewed Bionic port for `mod_ssl`, depending on the expression-parser fix.

Other vulnerabilities and modules not loaded on mrscoulter are out of scope of this interim RC.

The five package names are `apache2`, `apache2-bin`, `apache2-data`, `apache2-dev` and `apache2-utils`. Neither PHP binaries nor PHP dependencies are included. In tests the packages were installed alongside Niek's unmodified PHP 7.4.33 module.

**Installation**: back up `/etc/apache2` and keep the original Ubuntu package DEBs for rollback; extract `apache2-bionic-rc1-packages.tar.gz` and verify `sha256sum -c SHA256SUMS`. In a directory with *only the five Apache packages*, run `apt -s install ./*.deb` and check that **only the five Apache packages** are upgraded. Then perform the real `apt install ./*.deb`, followed by `apache2ctl configtest`, `systemctl status apache2` and service-level tests. Package scripts may restart Apache during the transaction; they do not wait for a manual restart.

**Rollback**: downgrade all five installed Apache packages to the original `2.4.29-1ubuntu4.27` together, using the original DEBs retained before installation. Do not attempt a partial Apache downgrade.

CI evidence: [original five-fix experiment](https://github.com/bilo1967/LegacyPackages/actions/runs/43712616135); [PHP 7.4.33 compatibility](https://github.com/bilo1967/LegacyPackages/actions/runs/43713119730).
