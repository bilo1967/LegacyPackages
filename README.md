# LegacyPackages

Security backports for legacy Ubuntu packages. The repository is public; this project is maintained independently and is **not an official Ubuntu or Apache distribution**.

## Apache 2.4 for Ubuntu 20.04 (Focal)

**RC1 available for testing:** [Apache 2.4.41 for Ubuntu 20.04 - RC1](https://github.com/bilo1967/LegacyPackages/releases/tag/apache2-2.4.41-focal-rc1).

- Base: Ubuntu Focal `apache2 2.4.41-4ubuntu3.23`.
- RC version: `2.4.41-4ubuntu3.23+unibo1~rc1`.
- Objective: security backport retaining Ubuntu packaging, configuration handling and existing Apache module ABI (no recompilation of PHP or external modules required in the tested deployment).
- 63 patches imported from Ubuntu Jammy's security patch series; four source patches excluded with [documented reasons](apache2/focal/README.md). The native Focal `CVE-2025-55753` retry-overflow issue was mitigated separately and regression-tested.
- [RC1 package build/test job passed](https://github.com/bilo1967/LegacyPackages/actions/runs/43698324239). Its release attachment step failed after build/test; the existing artifact is being reused rather than recompiled.
- Maintainer reports the five RC Debian packages installed on an existing Focal host and initial Apache/PHP functionality working. This is a field smoke test, **not** a guarantee for every deployment.

The original Apache `/etc/apache2` configuration is managed as normal Debian package conffiles. Preserve a backup and original Ubuntu `.deb` packages for rollback. PHP 8.3/8.4 packages were downloaded for disposable compatibility tests only; **they are not included in the Apache release and should not be upgraded as part of it**.

See [detailed build, test and recovery notes](apache2/focal/README.md), [RC1 release description](apache2/focal/RELEASE-RC1.md) and [patch manifest](apache2/focal/analysis/experimental-manifest.md).

**Security scope:** the patch import and runtime tests do not establish exact equivalence with Canonical's Ubuntu Pro/ESM packages or a formal comprehensive security audit. Prefer official security updates where feasible.

## Ubuntu 18.04 (Bionic)

No Bionic binary release or working patch stream is provided. Although some recent CVEs also affect Apache 2.4.29, porting the Focal patch set would require significant new source-level adaptation. See [Bionic assessment](apache2/bionic-evaluation.md). The preferred paths are official Ubuntu Pro/ESM packages, upgrading the host, or migrating suitable services to Caddy + PHP-FPM instead of another broad backport.

## Sources, workflows and safety

- [Focal source branch](https://github.com/bilo1967/LegacyPackages/tree/backport/focal)
- [Experimental source import and regression workflow](.github/workflows/apache2-focal-experimental.yml)
- [RC1 draft/release asset workflow](.github/workflows/apache2-focal-rc-finalize.yml)
- [Focal source provenance](apache2/focal/source-provenance.md)

Builds and tests run in disposable Ubuntu 20.04 Docker environments. Never commit private keys, credentials, host-specific production configs or personally identifying data. Validate any binary on a test machine and retain a rollback plan.
