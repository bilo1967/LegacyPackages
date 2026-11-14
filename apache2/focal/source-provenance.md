# Focal source provenance and security baseline

## Starting source

Ubuntu official package pool contains:
- https://security.ubuntu.com/ubuntu/pool/main/a/apache2/apache2_2.4.41-4ubuntu3.23.dsc
- https://security.ubuntu.com/ubuntu/pool/main/a/apache2/apache2_2.4.41-4ubuntu3.23.debian.tar.xz
- https://security.ubuntu.com/ubuntu/pool/main/a/apache2/apache2_2.4.41.orig.tar.gz

Acquire via `dget -x https://security.ubuntu.com/ubuntu/pool/main/a/apache2/apache2_2.4.41-4ubuntu3.23.dsc` or `apt source apache2=2.4.41-4ubuntu3.23` with correct deb-src entries. Check source signatures/checksums and never blindly trust a rehosted archive.

## Current upstream Ubuntu advisory checkpoints (2026-11-14)

- https://ubuntu.com/security/notices/USN-9016-1 (2026-11-10): Focal target `2.4.41-4ubuntu3.23+esm10`.
- https://ubuntu.com/security/notices/USN-9090-1 (2026-11-12): Focal target `2.4.41-4ubuntu3.23+esm11`.
- https://ubuntu.com/security/notices/USN-8571-2: earlier HTTP/2 regression fix; avoid cherry-picking without tracking corrections.

**Important**: ESM source archive access and redistribution conditions still need verification. We have not obtained ESM source or compiled anything. Apache upstream, Jammy, and Focal patches are not automatically interchangeable.

## Required gate

Create a CVE-to-patch-to-test matrix for all relevant ESM updates from the public Focal baseline through `+esm11`; do not label the build a security fix before it is complete.
