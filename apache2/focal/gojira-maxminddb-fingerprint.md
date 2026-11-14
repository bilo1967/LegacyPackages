# gojira: mod_maxminddb binary fingerprint (2026-11-14)

Source: operator-provided, read-only inspection of installed module.

- Path: `/usr/lib/apache2/modules/mod_maxminddb.so`
- Ownership/mode: root:root, `0644`
- File size: 68,592 bytes
- ELF: 64-bit LSB shared object, x86-64, dynamically linked; includes debug info, not stripped
- GNU BuildID (SHA-1): `24e71a2e27ae1b43a9f16e15cac26a759bb7aa58`
- SHA-256: `e1ca42c89f1b36974595e036b5c1860c4bb4122dfa00337d2d38497630b211e3`
- `dpkg -S`: no owning package
- `ldd`: `libmaxminddb.so.0` from `/lib/x86_64-linux-gnu/`, `libc.so.6`, Linux loader and vDSO. No missing linked shared libraries in supplied output.
- The library dependencies do not establish compatibility with a future `libapache2` / Apache module ABI.
- `apache2ctl -t` output has not been supplied.

Regression gate: restore this exact .so from a private backup on the test image; verify loader, `apache2ctl -t`, functional MaxMindDB lookup/config in a staging vhost and logs. Do not commit the binary or private config.
