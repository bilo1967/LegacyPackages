# Jammy mod_md compatibility with Focal development headers

Diagnostic only; no module installation or CVE remediation.

- Environment: disposable Ubuntu 20.04 container, stock apache2-dev.
- Stage-3 diagnostic: Jammy http_ssl.h supplied from isolated include path.
- Minimum Apache 2.4.48 guard bypassed ONLY in disposable source copy.
- WARNING: any resulting module is unsupported and must NOT be loaded or deployed.
- ABI note: declarations do not provide missing Focal core/mod_ssl hooks or symbols.
- DSO output explicitly selected via apxs -o mod_md.so.
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

## Undefined dynamic symbols (first 100)

~~~text
                 U ACCESS_DESCRIPTION_free
                 U ASN1_INTEGER_free
                 U ASN1_INTEGER_to_BN
                 U ASN1_STRING_get0_data
                 U ASN1_STRING_length
                 U ASN1_STRING_to_UTF8
                 U ASN1_TIME_adj
                 U ASN1_TIME_diff
                 U ASN1_TIME_set
                 U BIO_ctrl
                 U BIO_free
                 U BIO_new
                 U BIO_new_file
                 U BIO_new_mem_buf
                 U BIO_read
                 U BIO_s_mem
                 U BN_bin2bn
                 U BN_bn2bin
                 U BN_bn2hex
                 U BN_free
                 U BN_num_bits
                 U BN_to_ASN1_INTEGER
                 U CRYPTO_free
                 U CRYPTO_malloc
                 U EC_curve_nid2nist
                 U EC_curve_nist2nid
                 U EC_get_builtin_curves
                 U ERR_clear_error
                 U ERR_error_string
                 U ERR_get_error
                 U EVP_DigestFinal
                 U EVP_DigestInit_ex
                 U EVP_DigestUpdate
                 U EVP_MD_CTX_free
                 U EVP_MD_CTX_new
                 U EVP_PKEY_CTX_ctrl
                 U EVP_PKEY_CTX_free
                 U EVP_PKEY_CTX_new_id
                 U EVP_PKEY_free
                 U EVP_PKEY_get0_RSA
                 U EVP_PKEY_id
                 U EVP_PKEY_keygen
                 U EVP_PKEY_keygen_init
                 U EVP_PKEY_paramgen_init
                 U EVP_PKEY_size
                 U EVP_SignFinal
                 U EVP_aes_256_cbc
                 U EVP_sha1
                 U EVP_sha256
                 U GENERAL_NAME_free
                 U HMAC
                 U OBJ_create
                 U OBJ_nid2ln
                 U OBJ_nid2sn
                 U OBJ_obj2nid
                 U OBJ_sn2nid
                 U OBJ_txt2nid
                 U OCSP_BASICRESP_free
                 U OCSP_CERTID_dup
                 U OCSP_CERTID_free
                 U OCSP_REQUEST_free
                 U OCSP_REQUEST_new
                 U OCSP_RESPONSE_free
                 U OCSP_SINGLERESP_get0_id
                 U OCSP_cert_to_id
                 U OCSP_check_nonce
                 U OCSP_id_get0_info
                 U OCSP_request_add0_id
                 U OCSP_request_add1_nonce
                 U OCSP_resp_count
                 U OCSP_resp_find_status
                 U OCSP_resp_get0
                 U OCSP_response_get1_basic
                 U OCSP_response_status
                 U OCSP_single_get0_status
                 U OPENSSL_init_crypto
                 U OPENSSL_sk_new_null
                 U OPENSSL_sk_num
                 U OPENSSL_sk_pop_free
                 U OPENSSL_sk_push
                 U OPENSSL_sk_value
                 U PEM_read_X509
                 U PEM_read_bio_PrivateKey
                 U PEM_read_bio_X509
                 U PEM_write_X509
                 U PEM_write_bio_PKCS8PrivateKey
                 U PEM_write_bio_X509
                 U RAND_bytes
                 U RAND_seed
                 U RAND_status
                 U RSA_get0_key
                 U RSA_pkey_ctx_ctrl
                 U SCT_get0_log_id
                 U SCT_get0_signature
                 U SCT_get_signature_nid
                 U SCT_get_timestamp
                 U SCT_get_version
                 U X509V3_EXT_conf_nid
                 U X509V3_set_ctx
                 U X509_EXTENSION_free
~~~

Unresolved Apache symbols require separate Focal API review.

## Static ABI symbol audit

- Present only in other installed Apache modules: 0
- No provider found in inspected binaries: 103
- Details: symbol-audit.md

## Disposable-container load test

Exit code: 1

~~~text
apache2: Syntax error on line 146 of /etc/apache2/apache2.conf: Syntax error on line 1 of /etc/apache2/mods-enabled/md_candidate.load: Cannot load /repo/output/mod-md-compatibility/mod-md-source-diagnostic/.libs/mod_md.so into server: /repo/output/mod-md-compatibility/mod-md-source-diagnostic/.libs/mod_md.so: undefined symbol: ap_ssl_conn_is_ssl
Action '-t' failed.
The Apache error log may have more information.

~~~

This does not establish ABI or ACME/OCSP security compatibility.
