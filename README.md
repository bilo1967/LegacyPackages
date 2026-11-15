# LegacyPackages

Security backports for legacy Ubuntu packages. The repository is public; this project is maintained independently and is **not an official Ubuntu or Apache distribution**.

## Apache 2.4 for Ubuntu 20.04 (Focal)

**RC1 available for testing:** [Apache 2.4.41 for Ubuntu 20.04 - RC1](https://github.com/bilo1967/LegacyPackages/releases/tag/apache2-2.4.41-focal-rc1).

- Base: Ubuntu Focal `apache2 2.4.41-4ubuntu3.23`.
- RC version: `2.4.41-4ubuntu3.23+unibo1~rc1`.
- Objective: security backport retaining Ubuntu packaging, configuration handling and existing Apache module ABI (no recompilation of PHP or external modules required in the tested deployment).
- 63 patches imported from Ubuntu Jammy's security patch series; four source patches excluded with [documented reasons](https://github.com/bilo1967/LegacyPackages/blob/backport/focal/apache2/focal/README.md). The native Focal `CVE-2025-55753` retry-overflow issue was mitigated separately and regression-tested.
- [RC1 package build/test job passed](https://github.com/bilo1967/LegacyPackages/actions/runs/43698324239). Its release attachment step failed after build/test; the existing artifact is being reused rather than recompiled.
- Maintainer reports the five RC Debian packages installed on an existing Focal host and initial Apache/PHP functionality working. This is a field smoke test, **not** a guarantee for every deployment.

The original Apache `/etc/apache2` configuration is managed as normal Debian package conffiles. Preserve a backup and original Ubuntu `.deb` packages for rollback. PHP 8.3/8.4 packages were downloaded for disposable compatibility tests only; **they are not included in the Apache release and should not be upgraded as part of it**.

See [detailed build, test and recovery notes](https://github.com/bilo1967/LegacyPackages/blob/backport/focal/apache2/focal/README.md), [RC1 release description](https://github.com/bilo1967/LegacyPackages/blob/backport/focal/apache2/focal/RELEASE-RC1.md) and [patch manifest](https://github.com/bilo1967/LegacyPackages/blob/backport/focal/apache2/focal/analysis/experimental-manifest.md).

**Security scope:** the patch import and runtime tests do not establish exact equivalence with Canonical's Ubuntu Pro/ESM packages or a formal comprehensive security audit. Prefer official security updates where feasible.

## Apache 2.4 for Ubuntu 18.04 (Bionic)

**Interim RC1 for testing:** `2.4.29-1ubuntu4.27+bilo1~rc1`, amd64, [pre-release `apache2-2.4.29-bionic-rc1`](https://github.com/bilo1967/LegacyPackages/releases/tag/apache2-2.4.29-bionic-rc1).

- Selective backport of **five** recent fixes: CVE-2026-63292, CVE-2026-56153, CVE-2026-56154, CVE-2026-44119 and CVE-2026-59797.
- Preserves the distro package layout and module ABI. No PHP packages included or recompiled.
- [Build and full APT upgrade/compatibility checks succeeded](https://github.com/bilo1967/LegacyPackages/actions/runs/43718996495), including unchanged `mod_php` 7.4.33 from Niek.
- Maintainer installed the RC1 on the Bionic host and reports successful functional tests.
- Other CVEs remain outstanding: this is **not** a complete security backport or Canonical ESM-equivalent package.

See [RC1 README](https://github.com/bilo1967/LegacyPackages/blob/backport/bionic/apache2/bionic/RC1-README.md), [technical notes](https://github.com/bilo1967/LegacyPackages/blob/backport/bionic/apache2/bionic/README.md) and [Bionic source branch](https://github.com/bilo1967/LegacyPackages/tree/backport/bionic).

## Sources, workflows and safety

The full Focal source history and technical notes live on `backport/focal`; the default `main` branch is an overview, not the build source.

- [Focal source branch](https://github.com/bilo1967/LegacyPackages/tree/backport/focal)
- [Experimental source import and regression workflow](https://github.com/bilo1967/LegacyPackages/blob/backport/focal/.github/workflows/apache2-focal-experimental.yml)
- [RC1 draft/release asset workflow](https://github.com/bilo1967/LegacyPackages/blob/backport/focal/.github/workflows/apache2-focal-rc-finalize.yml)
- [Focal source provenance](https://github.com/bilo1967/LegacyPackages/blob/backport/focal/apache2/focal/source-provenance.md)

Builds and tests run in disposable Ubuntu 20.04 Docker environments. Never commit private keys, credentials, host-specific production configs or personally identifying data. Validate any binary on a test machine and retain a rollback plan.
