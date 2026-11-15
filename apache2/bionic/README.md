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
`2.4.29-1ubuntu4.27+bilo0~experimental1` during
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

## Second milestone — focused Bionic backport with Niek PHP compatibility

**Build + smoke tests succeeded (15 November 2026).** Exact Bionic base:
`2.4.29-1ubuntu4.27`; experimental Debian version:
`2.4.29-1ubuntu4.27+bilo0~experimental2`.

Five security patch entries are included:

- Imported unchanged from the verified Jammy quilt series: `CVE-2026-63292`, `CVE-2026-56153`.
- Bionic-specific port: `CVE-2026-56154` (`mod_rewrite` subrequest lifetime; both LA-U/LA-F branches).
- Bionic-specific port: `CVE-2026-44119` (the restricted file-function expression parser prerequisite, preserving upstream restrictions).
- Bionic-specific port: `CVE-2026-59797` (`mod_ssl` SSLRequire; depends on `44119`).

[Successful package build and Apache smoke test](https://github.com/bilo1967/LegacyPackages/actions/runs/43712616135)
produced the `apache2-bionic-4CVE-EXPERIMENTAL` artifact (historical artifact name; **it contains five** patch entries, including the parser prerequisite). Checks included package installation, `mpm_prefork`, loaded SSL/rewrite/proxy modules, Apache syntax and an HTTP response.

[Successful compatibility run with the **actual Niek Ubuntu 18.04 PHP 7.4.33 packages**](https://github.com/bilo1967/LegacyPackages/actions/runs/43713119730)
retrieved the vendor's published `v7.4.33-2` package archive, checked its SHA256 manifest, then in a fresh Ubuntu 18.04 Docker container installed the already-built Apache packages **without recompiling** them, loaded `libapache2-mod-php7.4` with prefork and confirmed that PHP 7.4.33 responded to an HTTP request as `apache2handler`. PHP packages were temporary test inputs, **not distributed in the Apache artifact and not to be reinstalled on mrscoulter**.

Pending/deferred source fixes principally affect modules absent from mrscoulter's loaded set:
`CVE-2026-46729` (`mod_heartmonitor`), `CVE-2026-47360` (`mod_session_cookie`), and `CVE-2026-63686` (`mod_xml2enc`).
The host's use of `mod_auth_digest`, HTTP/2, WebDAV and `mod_vhost_alias` was also absent in the inventory. These omissions **do not mean the wider Bionic security backlog is complete**.

**Release status:** experimental technical proof, **not yet a production release**.
No changes were made to mrscoulter. Before deploying a candidate, create an explicit RC version, retain original Bionic DEBs and `/etc/apache2` backup, confirm an `apt -s install` transaction affecting only the Apache packages, then stage a service restart and functional checks. The standard Apache module ABI was preserved, and Niek mod_php loads successfully, but the selected security behavior has not undergone a comprehensive independent exploit-focused audit. This package is **not Canonical ESM-equivalent**.

## Interim RC1 for test deployment

RC Debian version: `2.4.29-1ubuntu4.27+bilo1~rc1`. The RC is generated
from the **same five source patch entries** as the successful experimental
build. It is a partial security backport for the modules used on
`mrscoulter`, not a statement that Ubuntu 18.04 is fully secured or ESM-equivalent.

The CI candidate workflow compiles in a disposable Ubuntu 18.04 container,
checks the five intended Apache `.deb` versions, simulates the upgrade over
the original Ubuntu packages **with Niek PHP 7.4.33 installed**, requires no
PHP package transaction, then installs the RC and executes an HTTP PHP request.
The published artifact includes the five Apache packages, their SHA256 checksums,
and a tar archive retaining the exact Debian filenames with `+` and `~`.

For deployment preserve `/etc/apache2`, installed package versions and the
original Ubuntu `.deb` packages. Inspect `apt -s install ./*.deb` before
proceeding. The dpkg maintainer scripts may restart Apache automatically;
arrange a maintenance window and check the vhosts after installation.

### RC1 build completed and upgrade-tested — 15 November 2026

[**Successful RC1 workflow #2**](https://github.com/bilo1967/LegacyPackages/actions/runs/43716982446),
artifact `apache2-bionic-RC1` (retained for 30 days). This action produced
version `2.4.29-1ubuntu4.27+bilo1~rc1` and passed all steps.

The artifact contains the five `.deb` files, `SHA256SUMS`,
`PATCH-MANIFEST.md`, `RELEASE-NOTES.md` and
`apache2-bionic-rc1-packages.tar.gz`, which retains exact Debian package
filenames. PHP packages are not included.

A fresh Ubuntu 18.04 container was prepared with *original Ubuntu Apache
2.4.29-1ubuntu4.27*, `apache2-dev`, and Niek's unmodified
`libapache2-mod-php7.4` 7.4.33 (with its original local dependencies).
**The APT simulation proposed upgrading only the five Apache packages.**
After installing the RC, a comparison of PHP package versions before/after
showed no changes. The server passed `apache2ctl configtest`, loaded the
prefork MPM, SSL, rewrite and PHP modules, and served a PHP 7.4.33 page
through `apache2handler`.

**Deployment checklist for mrscoulter**: preserve the current `/etc/apache2`
tree and original `2.4.29-1ubuntu4.27` DEBs; extract the RC archive in an
otherwise empty directory; run `sha256sum -c SHA256SUMS`, then
`apt -s install ./*.deb` and review the exact package transaction.
Proceed only if the simulated upgrade touches those five Apache packages
and no PHP packages. Be aware that package maintainer scripts may restart
Apache automatically. After installation, check `apache2ctl configtest`,
`systemctl status apache2`, loaded modules and critical vhosts.

**Package naming:** the maintained Bionic RC uses the maintainer prefix `bilo` rather than an institutional identifier. Earlier experiment runs were built with the old suffix; their linked CI logs and artifacts remain historical evidence, not the release to install.
