# Bionic patch context inspection (source-only)

Raw vendor patches are retained under `patches/` for review.
All commands use dry-run with fuzz=0; no binary has been built.

## CVE-2026-56154.patch

### Dry-run output

```text
checking file modules/mappers/mod_rewrite.c
Hunk #1 succeeded at 1925 (offset -15 lines).
Hunk #2 FAILED at 1978.
1 out of 2 hunks FAILED
```

### Source file: `modules/mappers/mod_rewrite.c`

No unambiguous hunk context anchor found; inspect the raw patch.

## CVE-2026-63686.patch

### Dry-run output

```text
checking file modules/filters/mod_xml2enc.c
Hunk #1 succeeded at 485 (offset -37 lines).
Hunk #2 succeeded at 499 (offset -37 lines).
Hunk #3 FAILED at 545.
Hunk #4 succeeded at 517 (offset -36 lines).
1 out of 4 hunks FAILED
```

### Source file: `modules/filters/mod_xml2enc.c`

Bionic lines 476-505 around anchor:

```c
476:                                   ctx->bblen - ctx->bytes);
477:                     consumed = insz;
478:                     rv2 = ap_fwrite(f->next, ctx->bbnext, ctx->buf,
479:                                     (apr_size_t)ctx->bblen - ctx->bytes);
480:                     if (rv2 != APR_SUCCESS) {
481:                         ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv2, f->r, APLOGNO(01442)
482:                                       "ap_fwrite failed");
483:                         return rv2;
484:                     }
485:                     switch (rv) {
486:                     case APR_SUCCESS:
487:                         continue;
488:                     case APR_EINCOMPLETE:
489:                         ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, APLOGNO(01443)
490:                                       "INCOMPLETE");
491:                         continue;     /* If outbuf too small, go round again.
492:                                        * If it was inbuf, we'll break out when
493:                                        * we test ctx->bytes == ctx->bblen
494:                                        */
495:                     case APR_EINVAL: /* try skipping one bad byte */
496:                         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, APLOGNO(01444)
497:                                    "Skipping invalid byte(s) in input stream!");
498:                         --insz;
499:                         continue;
500:                     default:
501:                         /* Erk!  What's this?
502:                          * Bail out, flush, and hope to eat the buf raw
503:                          */
504:                         ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, APLOGNO(01445)
505:                                       "Failed to convert input; trying it raw") ;
```

Bionic lines 491-520 around anchor:

```c
491:                         continue;     /* If outbuf too small, go round again.
492:                                        * If it was inbuf, we'll break out when
493:                                        * we test ctx->bytes == ctx->bblen
494:                                        */
495:                     case APR_EINVAL: /* try skipping one bad byte */
496:                         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, APLOGNO(01444)
497:                                    "Skipping invalid byte(s) in input stream!");
498:                         --insz;
499:                         continue;
500:                     default:
501:                         /* Erk!  What's this?
502:                          * Bail out, flush, and hope to eat the buf raw
503:                          */
504:                         ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, APLOGNO(01445)
505:                                       "Failed to convert input; trying it raw") ;
506:                         ctx->convset = NULL;
507:                         rv = ap_fflush(f->next, ctx->bbnext);
508:                         if (rv != APR_SUCCESS)
509:                             ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, f->r, APLOGNO(01446)
510:                                           "ap_fflush failed");
511:                         else
512:                             rv = ap_pass_brigade(f->next, ctx->bbnext);
513:                     }
514:                 }
515:             } else {
516:                 ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, APLOGNO(01447)
517:                               "xml2enc: error reading data") ;
518:             }
519:             if (bdestroy)
520:                 apr_bucket_destroy(bdestroy);
```

Bionic lines 499-528 around anchor:

```c
499:                         continue;
500:                     default:
501:                         /* Erk!  What's this?
502:                          * Bail out, flush, and hope to eat the buf raw
503:                          */
504:                         ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, APLOGNO(01445)
505:                                       "Failed to convert input; trying it raw") ;
506:                         ctx->convset = NULL;
507:                         rv = ap_fflush(f->next, ctx->bbnext);
508:                         if (rv != APR_SUCCESS)
509:                             ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, f->r, APLOGNO(01446)
510:                                           "ap_fflush failed");
511:                         else
512:                             rv = ap_pass_brigade(f->next, ctx->bbnext);
513:                     }
514:                 }
515:             } else {
516:                 ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, APLOGNO(01447)
517:                               "xml2enc: error reading data") ;
518:             }
519:             if (bdestroy)
520:                 apr_bucket_destroy(bdestroy);
521:             if (rv != APR_SUCCESS)
522:                 return rv;
523:         }
524:     }
525:     return APR_SUCCESS;
526: }
527: static apr_status_t xml2enc_charset(request_rec* r, xmlCharEncoding* encp,
528:                                     const char** encoding)
```

Bionic lines 510-539 around anchor:

```c
510:                                           "ap_fflush failed");
511:                         else
512:                             rv = ap_pass_brigade(f->next, ctx->bbnext);
513:                     }
514:                 }
515:             } else {
516:                 ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, APLOGNO(01447)
517:                               "xml2enc: error reading data") ;
518:             }
519:             if (bdestroy)
520:                 apr_bucket_destroy(bdestroy);
521:             if (rv != APR_SUCCESS)
522:                 return rv;
523:         }
524:     }
525:     return APR_SUCCESS;
526: }
527: static apr_status_t xml2enc_charset(request_rec* r, xmlCharEncoding* encp,
528:                                     const char** encoding)
529: {
530:     xml2ctx* ctx = ap_get_module_config(r->request_config, &xml2enc_module);
531:     if (!ctx || !(ctx->flags & ENC_INITIALISED)) {
532:         return APR_EAGAIN;
533:     }
534:     *encp = ctx->xml2enc;
535:     *encoding = ctx->encoding;
536:     return HAVE_ENCODING(ctx->xml2enc) ? APR_SUCCESS : APR_EGENERAL;
537: }
538: 
539: #define PROTO_FLAGS AP_FILTER_PROTO_CHANGE|AP_FILTER_PROTO_CHANGE_LENGTH
```

## CVE-2026-59797.patch

### Dry-run output

```text
checking file modules/ssl/ssl_engine_config.c
Hunk #1 succeeded at 1347 (offset -60 lines).
```

### Source file: `modules/ssl/ssl_engine_config.c`

Bionic lines 1337-1366 around anchor:

```c
1337: const char *ssl_cmd_SSLRequire(cmd_parms *cmd,
1338:                                void *dcfg,
1339:                                const char *arg)
1340: {
1341:     SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
1342:     ap_expr_info_t *info = apr_pcalloc(cmd->pool, sizeof(ap_expr_info_t));
1343:     ssl_require_t *require;
1344:     const char *errstring;
1345: 
1346:     info->flags = AP_EXPR_FLAG_SSL_EXPR_COMPAT;
1347:     info->filename = cmd->directive->filename;
1348:     info->line_number = cmd->directive->line_num;
1349:     info->module_index = APLOG_MODULE_INDEX;
1350:     errstring = ap_expr_parse(cmd->pool, cmd->temp_pool, info, arg, NULL);
1351:     if (errstring) {
1352:         return apr_pstrcat(cmd->pool, "SSLRequire: ", errstring, NULL);
1353:     }
1354: 
1355:     require = apr_array_push(dc->aRequirement);
1356:     require->cpExpr = arg;
1357:     require->mpExpr = info;
1358: 
1359:     return NULL;
1360: }
1361: 
1362: const char *ssl_cmd_SSLRenegBufferSize(cmd_parms *cmd, void *dcfg, const char *arg)
1363: {
1364:     SSLDirConfigRec *dc = dcfg;
1365:     int val;
1366: 
```

## CVE-2026-46729.patch

### Dry-run output

```text
checking file modules/cluster/mod_heartmonitor.c
Hunk #1 succeeded at 748 (offset 1 line).
Hunk #2 succeeded at 759 (offset 1 line).
Hunk #3 succeeded at 791 (offset 1 line).
```

### Source file: `modules/cluster/mod_heartmonitor.c`

Bionic lines 738-767 around anchor:

```c
738:     return OK;
739: }
740: 
741: static int hm_handler(request_rec *r)
742: {
743:     apr_bucket_brigade *input_brigade;
744:     apr_size_t len;
745:     char *buf;
746:     apr_status_t status;
747:     apr_table_t *tbl;
748:     hm_server_t hmserver;
749:     char *ip;
750:     hm_ctx_t *ctx;
751: 
752:     if (strcmp(r->handler, "heartbeat")) {
753:         return DECLINED;
754:     }
755:     if (r->method_number != M_POST) {
756:         return HTTP_METHOD_NOT_ALLOWED;
757:     }
758: 
759:     len = MAX_MSG_LEN;
760:     ctx = ap_get_module_config(r->server->module_config,
761:             &heartmonitor_module);
762: 
763:     buf = apr_pcalloc(r->pool, MAX_MSG_LEN);
764:     input_brigade = apr_brigade_create(r->connection->pool, r->connection->bucket_alloc);
765:     status = ap_get_brigade(r->input_filters, input_brigade, AP_MODE_READBYTES, APR_BLOCK_READ, MAX_MSG_LEN);
766:     if (status != APR_SUCCESS) {
767:         return ap_map_http_request_error(status, HTTP_BAD_REQUEST);
```

Bionic lines 746-775 around anchor:

```c
746:     apr_status_t status;
747:     apr_table_t *tbl;
748:     hm_server_t hmserver;
749:     char *ip;
750:     hm_ctx_t *ctx;
751: 
752:     if (strcmp(r->handler, "heartbeat")) {
753:         return DECLINED;
754:     }
755:     if (r->method_number != M_POST) {
756:         return HTTP_METHOD_NOT_ALLOWED;
757:     }
758: 
759:     len = MAX_MSG_LEN;
760:     ctx = ap_get_module_config(r->server->module_config,
761:             &heartmonitor_module);
762: 
763:     buf = apr_pcalloc(r->pool, MAX_MSG_LEN);
764:     input_brigade = apr_brigade_create(r->connection->pool, r->connection->bucket_alloc);
765:     status = ap_get_brigade(r->input_filters, input_brigade, AP_MODE_READBYTES, APR_BLOCK_READ, MAX_MSG_LEN);
766:     if (status != APR_SUCCESS) {
767:         return ap_map_http_request_error(status, HTTP_BAD_REQUEST);
768:     }
769:     apr_brigade_flatten(input_brigade, buf, &len);
770: 
771:     /* we can't use hm_processmsg because it uses hm_get_server() */
772:     buf[len] = '\0';
773:     tbl = apr_table_make(r->pool, 10);
774:     qs_to_table(buf, tbl, r->pool);
775:     apr_sockaddr_ip_get(&ip, r->connection->client_addr);
```

Bionic lines 763-792 around anchor:

```c
763:     buf = apr_pcalloc(r->pool, MAX_MSG_LEN);
764:     input_brigade = apr_brigade_create(r->connection->pool, r->connection->bucket_alloc);
765:     status = ap_get_brigade(r->input_filters, input_brigade, AP_MODE_READBYTES, APR_BLOCK_READ, MAX_MSG_LEN);
766:     if (status != APR_SUCCESS) {
767:         return ap_map_http_request_error(status, HTTP_BAD_REQUEST);
768:     }
769:     apr_brigade_flatten(input_brigade, buf, &len);
770: 
771:     /* we can't use hm_processmsg because it uses hm_get_server() */
772:     buf[len] = '\0';
773:     tbl = apr_table_make(r->pool, 10);
774:     qs_to_table(buf, tbl, r->pool);
775:     apr_sockaddr_ip_get(&ip, r->connection->client_addr);
776:     hmserver.ip = ip;
777:     hmserver.port = 80;
778:     if (apr_table_get(tbl, "port") != NULL)
779:         hmserver.port = atoi(apr_table_get(tbl, "port"));
780:     hmserver.busy = atoi(apr_table_get(tbl, "busy"));
781:     hmserver.ready = atoi(apr_table_get(tbl, "ready"));
782:     hmserver.seen = apr_time_now();
783:     hm_update_stat(ctx, &hmserver, r->pool);
784: 
785:     ap_set_content_type(r, "text/plain");
786:     ap_set_content_length(r, 2);
787:     ap_rputs("OK", r);
788:     ap_rflush(r);
789: 
790:     return OK;
791: }
792: 
```

## CVE-2026-47360.patch

### Dry-run output

```text
checking file modules/session/mod_session_cookie.c
Hunk #1 succeeded at 145 (offset 3 lines).
checking file server/util_cookies.c
```

### Source file: `modules/session/mod_session_cookie.c`

Bionic lines 135-164 around anchor:

```c
135:         name = conf->name2;
136:     }
137:     else if (conf->name_set) {
138:         name = conf->name;
139:     }
140:     else {
141:         return DECLINED;
142:     }
143: 
144:     /* first look in the notes */
145:     note = apr_pstrcat(m->pool, MOD_SESSION_COOKIE, name, NULL);
146:     zz = (session_rec *)apr_table_get(m->notes, note);
147:     if (zz) {
148:         *z = zz;
149:         return OK;
150:     }
151: 
152:     /* otherwise, try parse the cookie */
153:     ap_cookie_read(r, name, &val, conf->remove);
154: 
155:     /* create a new session and return it */
156:     zz = (session_rec *) apr_pcalloc(m->pool, sizeof(session_rec));
157:     zz->pool = m->pool;
158:     zz->entries = apr_table_make(m->pool, 10);
159:     zz->encoded = val;
160:     *z = zz;
161: 
162:     /* put the session in the notes so we don't have to parse it again */
163:     apr_table_setn(m->notes, note, (char *)zz);
164: 
```

### Source file: `server/util_cookies.c`

Bionic lines 207-236 around anchor:

```c
207:                 }
208:                 v->encoded = apr_pstrdup(v->r->pool, trim + len);
209:                 eat = 1;
210:             }
211:             else {
212:                 if (*trim != '$') {
213:                     cookies++;
214:                     eat = 0;
215:                 }
216:                 if (!eat) {
217:                     new_cookie = apr_pstrcat(v->r->pool, new_cookie, sep, next2, NULL);
218:                 }
219:             }
220:             next2 = apr_strtok(NULL, semi, &last2);
221:             sep = semi;
222:         }
223: 
224:         next1 = apr_strtok(NULL, comma, &last1);
225:         sep = comma;
226:     }
227: 
228:     /* any cookies left over? */
229:     if (cookies) {
230:         apr_table_addn(v->new_cookies, key, new_cookie);
231:     }
232: 
233:     return 1;
234: }
235: 
236: /**
```

