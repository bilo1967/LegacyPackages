# gojira (Ubuntu 20.04 Focal) — Apache compatibility inventory

Captured from operator-provided commands on 2026-11-14. This is **not** a completed security assessment.

## Baseline
- `apache2`, `apache2-bin`, `apache2-data`, `apache2-dev`, `apache2-utils`: `2.4.41-4ubuntu3.23` (amd64).
- Apache runtime: `2.4.41`; build timestamp `2025-04-02T18:34:29`.
- Module Magic Number: `20120211:88`.
- APR `1.6.5`, APR-UTIL `1.6.1`.
- MPM: **prefork**, non-threaded.
- `/etc/apache2` is HTTPD_ROOT.

## Enabled / loaded modules relevant to regression testing
- Authentication/access: `access_compat`, `auth_basic`, `authn_core`, `authn_file`, `authz_core`, `authz_groupfile`, `authz_host`, `authz_user`.
- Requests/routing: `alias`, `actions`, `rewrite`, `headers`, `remoteip`, `substitute`, `filter`, `setenvif`, `reqtimeout`.
- Proxy: `proxy`, `proxy_fcgi`, `proxy_http`, `proxy_wstunnel`.
- TLS: `ssl`, `socache_shmcb`.
- External/optional: `fcgid`, `maxminddb`, `php7_module`.
- Others: `autoindex`, `deflate`, `dir`, `env`, `mime`, `negotiation`, `status`.
- `http2_module` **NOT loaded** in the supplied output. This is not proof that no other vulnerability applies.

## Installed package facts
- `libapache2-mod-fcgid`: `1:2.3.9-4`.
- `libapache2-mod-php7.4`: `1:7.4.33-31+php7.2~ubuntu20.04.1`.
- `libapache2-mod-php8.3`: `8.3.36-1+0~20261021.88+ubuntu22.04~1.gbp250f7c+legacy1~ubuntu20.04`.
- `libnghttp2-14:amd64`: `1.40.0-1ubuntu0.3`.
- PHP-FPM installed: 7.4, 8.3, 8.4 (and 5.6, declared out of scope by operator).
- `php7_module` is loaded, but command output alone does not identify every vhost's PHP handler.
- Some `dpkg-query` matches have a blank version; these may be virtual package matches, not installed files. Verify with explicit dpkg status before interpreting.
- `mod_maxminddb` loads, but its package origin/version are not yet known.

## Risks / acceptance checks
1. Preserve `prefork` and `mod_php` compatibility; no implicit MPM switch.
2. Preserve module ABI, especially `fcgid` and `maxminddb` and any locally compiled modules.
3. Preserve `proxy_fcgi`, `proxy_http`, `proxy_wstunnel` behavior and WebSocket upgrades.
4. Regression-test `rewrite`, `headers`, `remoteip`, TLS, vhost routing, status, and PHP-FPM handlers.
5. Validate all applicable CVEs since the last standard Focal update; security update `USN-9090-1` specifies Focal `2.4.41-4ubuntu3.23+esm11`; `USN-9016-1` specifies `+esm10`. Don't infer that cherry-picking latest patches alone suffices.
6. Do not install builds on production without test VM / snapshot, package review, and rollback plan.

## Next non-destructive inventory commands

```sh
dpkg -S /usr/lib/apache2/modules/mod_maxminddb.so /usr/lib/apache2/modules/mod_fcgid.so /usr/lib/apache2/modules/libphp7.4.so 2>&1
dpkg-query -W -f='${binary:Package} ${Status} ${Version}\n' 'libapache2-mod-*' 'apache2*' 2>/dev/null
apache2ctl -t
find /etc/apache2/mods-enabled -maxdepth 1 -type l -printf '%f -> %l\n' | sort
```

Do not commit output containing credentials, IPs or vhost configuration.
