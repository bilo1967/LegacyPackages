# Jammy mod_md compatibility with Focal development headers

Diagnostic only; no module installation or CVE remediation.

- Environment: disposable Ubuntu 20.04 container, stock apache2-dev.
- Stage-3 diagnostic: Jammy http_ssl.h supplied from isolated include path.
- Minimum Apache 2.4.48 guard bypassed ONLY in disposable source copy.
- WARNING: any resulting module is unsupported and must NOT be loaded or deployed.
- ABI note: declarations do not provide missing Focal core/mod_ssl hooks or symbols.
- Source: Ubuntu Jammy patched Apache 2.4.52-1ubuntu4.27.
- Module object count: 28 (complete Jammy config2.m4 md_objs).
- Compile status: **COMPILED_UNSUPPORTED** (exit code 0).
- Full log: compiler.log.

## First compiler diagnostics

~~~text
/repo/output/mod-md-compatibility/mod-md-source-diagnostic/mod_md.c:1602:2: warning: #warning "DIAGNOSTIC ONLY: unsupported Focal Apache API; never deploy this module" [-Wcpp]
~~~

A compile success does not establish runtime/API compatibility with
the patched Focal Apache, ACME issuance, renewal, or OCSP behavior.

**Missing shared object after successful compiler exit.**
