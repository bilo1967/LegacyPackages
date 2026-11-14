# LegacyPackages

Repository for controlled Debian/Ubuntu package security backports.

## Apache 2.4

- `apache2/focal/`: Ubuntu 20.04 (Focal) workstream; baseline `2.4.41-4ubuntu3.23`.
- `apache2/bionic/`: Ubuntu 18.04 (Bionic) workstream; baseline to be verified against the target host.
- Keep Ubuntu's `debian/` packaging and apply reviewed, attributable security patches.
- Build in isolated, release-matched environments; do not build or deploy on production hosts.
- Track CVE applicability and test results before considering any packages releasable.

## Status

**Planning only.** No security patches have been applied or validated; no packages have been built. Do not deploy packages from this repository until build, regression, and security checks have passed.

## Operational precautions

Never commit private keys, certificates, credentials, customer data, or production Apache configuration. Keep source provenance and patch references alongside changes. Prefer signed APT publication when artifacts are eventually released.
