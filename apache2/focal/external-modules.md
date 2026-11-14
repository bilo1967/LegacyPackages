# gojira — third-party Apache modules follow-up (2026-11-14)

Operator reports from `dpkg -S`:

- `/usr/lib/apache2/modules/mod_maxminddb.so`: **not owned by any dpkg package**. Likely a manual build, unconfirmed. Retain exact binary for rollback and recover source/build flags if possible.
- `/usr/lib/apache2/modules/mod_fcgid.so`: owned by `libapache2-mod-fcgid`.
- `/usr/lib/apache2/modules/libphp7.4.so`: owned by `libapache2-mod-php7.4`.
- Operator identifies https://github.com/Niek/php7 as provenance for the PHP 7.4 security backport. That project's releases describe distro-specific builds using native libraries; independently validate the deployed package.

## Compatibility requirement
Keep module magic **major 20120211**, currently reported as `20120211:88`; check resulting major/minor and run loading/regression tests with the existing PHP, fcgid and maxminddb modules. A matching MMN is necessary but not a complete assurance of ABI/runtime safety.

## Follow-up on a non-production-compatible host (read-only on gojira)

```sh
apache2ctl -t
ls -l /usr/lib/apache2/modules/mod_maxminddb.so
file /usr/lib/apache2/modules/mod_maxminddb.so
ldd /usr/lib/apache2/modules/mod_maxminddb.so
sha256sum /usr/lib/apache2/modules/mod_maxminddb.so
apt-cache policy libapache2-mod-php7.4 libapache2-mod-fcgid
```

`ldd` should only be used on binaries already trusted and installed locally. Do not publish hostname-specific config, keys, private path details or IP data.

The previous user message included `apache2ctl -t` as a command, **not its output**: the syntax result remains unknown.
