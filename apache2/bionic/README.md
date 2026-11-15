# Apache 2.4 Bionic — narrow security backport

**Phase:** source and exposure triage only; **no** Bionic patched binaries available yet.

Target: `mrscoulter` (Ubuntu 18.04 / Apache 2.4.29). Exact installed Ubuntu revision and module inventory must be confirmed before modifying code. This branch is intentionally independent of the completed Focal RC.

The project prioritizes the high-impact CVEs disclosed on **7 October, 14 October, 10 November and 12 November 2026**, rather than importing the entire 63-patch Focal/Jammy candidate inventory.

Read the [focused CVE shortlist and time-limited build strategy](priority-2026-11.md). Only patches affecting the real Bionic source and relevant server features should proceed into an interim package. The final Canonical ESM reference is `apache2 2.4.29-1ubuntu4.27+esm15` (USN-9090-1).

**Constraints:** preserve Bionic's binary module ABI and existing Apache/PHP integrations; never transplant Focal or Jammy binaries. Use a disposable Bionic build container; minimal CI runs; verify installed modules before choosing optional CVEs. A partial backport is not equivalent to Ubuntu Pro/ESM.
