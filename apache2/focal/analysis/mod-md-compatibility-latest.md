# Jammy mod_md compatibility with Focal development headers

Diagnostic only; no module installation or CVE remediation.

- Environment: disposable Ubuntu 20.04 container, stock apache2-dev.
- Stage-2 diagnostic: only Jammy http_ssl.h supplied from isolated include path.
- ABI note: declarations do not provide missing Focal core/mod_ssl hooks or symbols.
- Source: Ubuntu Jammy patched Apache 2.4.52-1ubuntu4.27.
- Module object count: 28 (complete Jammy config2.m4 md_objs).
- Compile status: **INCOMPATIBLE** (exit code 1).
- Full log: compiler.log.

## First compiler diagnostics

~~~text
/tmp/jammy/apache2-2.4.52/modules/md/mod_md.c:1602:2: error: #error "This version of mod_md requires Apache httpd 2.4.48 or newer."
apxs:Error: Command failed with rc=65536
~~~

A compile success does not establish runtime/API compatibility with
the patched Focal Apache, ACME issuance, renewal, or OCSP behavior.
