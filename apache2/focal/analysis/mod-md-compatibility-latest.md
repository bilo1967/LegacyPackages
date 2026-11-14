# Jammy mod_md compatibility with Focal development headers

Diagnostic only; no module installation or CVE remediation.

- Environment: disposable Ubuntu 20.04 container, stock apache2-dev.
- Source: Ubuntu Jammy patched Apache 2.4.52-1ubuntu4.27.
- Module object count: 28 (complete Jammy config2.m4 md_objs).
- Compile status: **INCOMPATIBLE** (exit code 1).
- Full log: compiler.log.

## First compiler diagnostics

~~~text
/tmp/jammy/apache2-2.4.52/modules/md/mod_md.c:26:10: fatal error: http_ssl.h: No such file or directory
apxs:Error: Command failed with rc=65536
~~~

A compile success does not establish runtime/API compatibility with
the patched Focal Apache, ACME issuance, renewal, or OCSP behavior.
