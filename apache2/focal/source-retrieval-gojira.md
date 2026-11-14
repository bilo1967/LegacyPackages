# Focal source retrieval on gojira (operator report, 2026-11-14)

Successfully ran `apt-get source apache2=2.4.41-4ubuntu3.23` from `/usr/local/src/apache2-backport` on production host `gojira`. No installed Apache package was changed by this command.

Retrieved:
- `apache2_2.4.41.orig.tar.gz`
- `apache2_2.4.41-4ubuntu3.23.debian.tar.xz`
- `apache2_2.4.41-4ubuntu3.23.dsc`
- unpacked/patched `apache2-2.4.41/`

Source archive total reported download: 10.6 MB. `dpkg-source` applied Debian/Ubuntu patch series successfully with no reported patch rejects; last displayed patch: `CVE-2024-38474-regression.patch`.

Apt warning: unsandboxed download as root because `_apt` could not access current destination; not an extraction failure. Future source retrieval preferable as non-root.

**Production caution**: Restrict activities on gojira to read-only source inspection for now. No package builds, package installations, service reload/restart, or tests that modify live Apache until isolation/rollback is defined.

## Next safe inventory commands

```sh
cd /usr/local/src/apache2-backport
dpkg-source --verify apache2_2.4.41-4ubuntu3.23.dsc
wc -l apache2-2.4.41/debian/patches/series
tail -n 25 apache2-2.4.41/debian/changelog
grep -nE '^(Package:|Build-Depends:|Build-Depends-Indep:)' apache2-2.4.41/debian/control
```

The `dpkg-source --verify` output can report signature-related warnings if no trusted Ubuntu signing key is available. Do not mistake archive checksum verification for a full signature-trust check.
