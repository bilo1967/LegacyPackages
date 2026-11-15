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

## CVE-2026-44119.patch

### Dry-run output

```text
checking file include/ap_expr.h
checking file modules/mappers/mod_rewrite.c
Hunk #1 FAILED at 3605.
1 out of 1 hunk FAILED
checking file modules/metadata/mod_setenvif.c
Hunk #1 FAILED at 424.
1 out of 1 hunk FAILED
checking file modules/proxy/mod_proxy_fcgi.c
Hunk #1 FAILED at 1276.
1 out of 1 hunk FAILED
checking file server/util_expr_eval.c
Hunk #1 succeeded at 432 (offset -1 lines).
Hunk #2 succeeded at 1635 (offset 2 lines).
Hunk #3 succeeded at 1673 (offset 2 lines).
Hunk #4 succeeded at 1687 (offset 2 lines).
Hunk #5 FAILED at 1749.
1 out of 5 hunks FAILED
```

### Source file: `include/ap_expr.h`

Bionic lines 56-85 around anchor:

```c
56: /** Use ssl_expr compatibility mode (changes the meaning of the comparison
57:  * operators)
58:  */
59: #define AP_EXPR_FLAG_SSL_EXPR_COMPAT       1
60: /** Don't add siginificant request headers to the Vary response header */
61: #define AP_EXPR_FLAG_DONT_VARY             2
62: /** Don't allow functions/vars that bypass the current request's access
63:  *  restrictions or would otherwise leak confidential information.
64:  *  Used by e.g. mod_include.
65:  */
66: #define AP_EXPR_FLAG_RESTRICTED            4
67: /** Expression evaluates to a string, not to a bool */
68: #define AP_EXPR_FLAG_STRING_RESULT         8
69: 
70: 
71: /**
72:  * Evaluate a parse tree, simple interface
73:  * @param r The current request
74:  * @param expr The expression to be evaluated
75:  * @param err Where an error message should be stored
76:  * @return > 0 if expression evaluates to true, == 0 if false, < 0 on error
77:  * @note err will be set to NULL on success, or to an error message on error
78:  * @note request headers used during evaluation will be added to the Vary:
79:  *       response header, unless ::AP_EXPR_FLAG_DONT_VARY is set.
80:  */
81: AP_DECLARE(int) ap_expr_exec(request_rec *r, const ap_expr_info_t *expr,
82:                              const char **err);
83: 
84: /**
85:  * Evaluate a parse tree, with access to regexp backreference
```

Bionic lines 254-283 around anchor:

```c
254: /** parameter struct passed to the lookup hook functions */
255: typedef struct {
256:     /** type of the looked up object */
257:     int type;
258: #define AP_EXPR_FUNC_VAR        0
259: #define AP_EXPR_FUNC_STRING     1
260: #define AP_EXPR_FUNC_LIST       2
261: #define AP_EXPR_FUNC_OP_UNARY   3
262: #define AP_EXPR_FUNC_OP_BINARY  4
263:     /** name of the looked up object */
264:     const char *name;
265: 
266:     int flags;
267: 
268:     apr_pool_t *pool;
269:     apr_pool_t *ptemp;
270: 
271:     /** where to store the function pointer */
272:     const void **func;
273:     /** where to store the function's context */
274:     const void **data;
275:     /** where to store the error message (if any) */
276:     const char **err;
277: 
278:     /** arg for pre-parsing (only if a simple string).
279:      *  For binary ops, this is the right argument. */
280:     const char *arg;
281: } ap_expr_lookup_parms;
282: 
283: /** Function for looking up the provider function for a variable, operator
```

### Source file: `modules/mappers/mod_rewrite.c`

Bionic lines 3471-3500 around anchor:

```c
3471:                              AP_REG_EXTENDED | ((newcond->flags & CONDFLAG_NOCASE)
3472:                                              ? AP_REG_ICASE : 0));
3473:         if (!regexp) {
3474:             return apr_pstrcat(cmd->pool, "RewriteCond: cannot compile regular "
3475:                                "expression '", a2, "'", NULL);
3476:         }
3477: 
3478:         newcond->regexp  = regexp;
3479:     }
3480:     else if (newcond->ptype == CONDPAT_AP_EXPR) {
3481:         unsigned int flags = newcond->flags & CONDFLAG_NOVARY ?
3482:                              AP_EXPR_FLAG_DONT_VARY : 0;
3483:         newcond->expr = ap_expr_parse_cmd(cmd, a2, flags, &err, NULL);
3484:         if (err)
3485:             return apr_psprintf(cmd->pool, "RewriteCond: cannot compile "
3486:                                 "expression \"%s\": %s", a2, err);
3487:     }
3488: 
3489:     return NULL;
3490: }
3491: 
3492: static const char *cmd_rewriterule_setflag(apr_pool_t *p, void *_cfg,
3493:                                            char *key, char *val)
3494: {
3495:     rewriterule_entry *cfg = _cfg;
3496:     int error = 0;
3497: 
3498:     switch (*key++) {
3499:     case 'b':
3500:     case 'B':
```

### Source file: `modules/metadata/mod_setenvif.c`

Bionic lines 414-443 around anchor:

```c
414:     }
415:     return add_setenvif_core(cmd, mconfig, fname, args);
416: }
417: 
418: static const char *add_setenvifexpr(cmd_parms *cmd, void *mconfig,
419:                                     const char *args)
420: {
421:     char *expr;
422:     sei_cfg_rec *sconf;
423:     sei_entry *new;
424:     const char *err;
425: 
426:     /*
427:      * Determine from our context into which record to put the entry.
428:      * cmd->path == NULL means we're in server-wide context; otherwise,
429:      * we're dealing with a per-directory setting.
430:      */
431:     sconf = (cmd->path != NULL)
432:       ? (sei_cfg_rec *) mconfig
433:       : (sei_cfg_rec *) ap_get_module_config(cmd->server->module_config,
434:                                                &setenvif_module);
435:     /* get expr */
436:     expr = ap_getword_conf(cmd->pool, &args);
437:     if (!*expr) {
438:         return apr_pstrcat(cmd->pool, "Missing expression for ",
439:                            cmd->cmd->name, NULL);
440:     }
441: 
442:     new = apr_array_push(sconf->conditionals);
443:     new->features = apr_table_make(cmd->pool, 2);
```

### Source file: `modules/proxy/mod_proxy_fcgi.c`

Bionic lines 1101-1130 around anchor:

```c
1101: }
1102: 
1103: 
1104: static const char *cmd_setenv(cmd_parms *cmd, void *in_dconf,
1105:                               const char *arg1, const char *arg2,
1106:                               const char *arg3)
1107: {
1108:     fcgi_dirconf_t *dconf = in_dconf;
1109:     const char *err;
1110:     sei_entry *new;
1111:     const char *envvar = arg2;
1112: 
1113:     new = apr_array_push(dconf->env_fixups);
1114:     new->cond = ap_expr_parse_cmd(cmd, arg1, 0, &err, NULL);
1115:     if (err) {
1116:         return apr_psprintf(cmd->pool, "Could not parse expression \"%s\": %s",
1117:                             arg1, err);
1118:     }
1119: 
1120:     if (envvar[0] == '!') {
1121:         /* Unset mode. */
1122:         if (arg3) {
1123:             return apr_psprintf(cmd->pool, "Third argument (\"%s\") is not "
1124:                                 "allowed when using ProxyFCGISetEnvIf's unset "
1125:                                 "mode (%s)", arg3, envvar);
1126:         }
1127:         else if (!envvar[1]) {
1128:             /* i.e. someone tried to give us a name of just "!" */
1129:             return "ProxyFCGISetEnvIf: \"!\" is not a valid variable name";
1130:         }
```

### Source file: `server/util_expr_eval.c`

Bionic lines 422-451 around anchor:

```c
422: 
423: AP_DECLARE(ap_expr_info_t*) ap_expr_parse_cmd_mi(const cmd_parms *cmd,
424:                                                  const char *expr,
425:                                                  unsigned int flags,
426:                                                  const char **err,
427:                                                  ap_expr_lookup_fn_t *lookup_fn,
428:                                                  int module_index)
429: {
430:     ap_expr_info_t *info = apr_pcalloc(cmd->pool, sizeof(ap_expr_info_t));
431:     info->filename = cmd->directive->filename;
432:     info->line_number = cmd->directive->line_num;
433:     info->flags = flags;
434:     info->module_index = module_index;
435:     *err = ap_expr_parse(cmd->pool, cmd->temp_pool, info, expr, lookup_fn);
436: 
437:     if (*err)
438:         return NULL;
439: 
440:     return info;
441: }
442: 
443: ap_expr_t *ap_expr_make(ap_expr_node_op_e op, const void *a1, const void *a2,
444:                       ap_expr_parse_ctx_t *ctx)
445: {
446:     ap_expr_t *node = apr_palloc(ctx->pool, sizeof(ap_expr_t));
447:     node->node_op   = op;
448:     node->node_arg1 = a1;
449:     node->node_arg2 = a2;
450:     return node;
451: }
```

Bionic lines 1619-1648 around anchor:

```c
1619: 
1620: static int op_strmatch(ap_expr_eval_ctx_t *ctx, const void *data,
1621:                        const char *arg1, const char *arg2)
1622: {
1623:     return (APR_SUCCESS == apr_fnmatch(arg2, arg1, 0));
1624: }
1625: 
1626: static int op_strcmatch(ap_expr_eval_ctx_t *ctx, const void *data,
1627:                         const char *arg1, const char *arg2)
1628: {
1629:     return (APR_SUCCESS == apr_fnmatch(arg2, arg1, APR_FNM_CASE_BLIND));
1630: }
1631: 
1632: struct expr_provider_single {
1633:     const void *func;
1634:     const char *name;
1635:     ap_expr_lookup_fn_t *arg_parsing_func;
1636:     int restricted;
1637: };
1638: 
1639: struct expr_provider_multi {
1640:     const void *func;
1641:     const char **names;
1642: };
1643: 
1644: static const struct expr_provider_multi var_providers[] = {
1645:     { misc_var_fn, misc_var_names },
1646:     { req_header_var_fn, req_header_var_names },
1647:     { request_var_fn, request_var_names },
1648:     { conn_var_fn, conn_var_names },
```

Bionic lines 1653-1682 around anchor:

```c
1653:     { osenv_func,           "osenv",          NULL, 0 },
1654:     { env_func,             "env",            NULL, 0 },
1655:     { req_table_func,       "resp",           NULL, 0 },
1656:     { req_table_func,       "req",            NULL, 0 },
1657:     /* 'http' as alias for 'req' for compatibility with ssl_expr */
1658:     { req_table_func,       "http",           NULL, 0 },
1659:     { req_table_func,       "note",           NULL, 0 },
1660:     { req_table_func,       "reqenv",         NULL, 0 },
1661:     { req_table_func,       "req_novary",     NULL, 0 },
1662:     { tolower_func,         "tolower",        NULL, 0 },
1663:     { toupper_func,         "toupper",        NULL, 0 },
1664:     { escape_func,          "escape",         NULL, 0 },
1665:     { unescape_func,        "unescape",       NULL, 0 },
1666:     { file_func,            "file",           NULL, 1 },
1667:     { filesize_func,        "filesize",       NULL, 1 },
1668:     { base64_func,          "base64",         NULL, 0 },
1669:     { unbase64_func,        "unbase64",       NULL, 0 },
1670:     { sha1_func,            "sha1",           NULL, 0 },
1671:     { md5_func,             "md5",            NULL, 0 },
1672:     { NULL, NULL, NULL}
1673: };
1674: 
1675: static const struct expr_provider_single unary_op_providers[] = {
1676:     { op_nz,        "n", NULL,             0 },
1677:     { op_nz,        "z", NULL,             0 },
1678:     { op_R,         "R", subnet_parse_arg, 0 },
1679:     { op_T,         "T", NULL,             0 },
1680:     { op_file_min,  "d", NULL,             1 },
1681:     { op_file_min,  "e", NULL,             1 },
1682:     { op_file_min,  "f", NULL,             1 },
```

Bionic lines 1667-1696 around anchor:

```c
1667:     { filesize_func,        "filesize",       NULL, 1 },
1668:     { base64_func,          "base64",         NULL, 0 },
1669:     { unbase64_func,        "unbase64",       NULL, 0 },
1670:     { sha1_func,            "sha1",           NULL, 0 },
1671:     { md5_func,             "md5",            NULL, 0 },
1672:     { NULL, NULL, NULL}
1673: };
1674: 
1675: static const struct expr_provider_single unary_op_providers[] = {
1676:     { op_nz,        "n", NULL,             0 },
1677:     { op_nz,        "z", NULL,             0 },
1678:     { op_R,         "R", subnet_parse_arg, 0 },
1679:     { op_T,         "T", NULL,             0 },
1680:     { op_file_min,  "d", NULL,             1 },
1681:     { op_file_min,  "e", NULL,             1 },
1682:     { op_file_min,  "f", NULL,             1 },
1683:     { op_file_min,  "s", NULL,             1 },
1684:     { op_file_link, "L", NULL,             1 },
1685:     { op_file_link, "h", NULL,             1 },
1686:     { op_file_xbit, "x", NULL,             1 },
1687:     { op_file_subr, "F", NULL,             0 },
1688:     { op_url_subr,  "U", NULL,             0 },
1689:     { op_url_subr,  "A", NULL,             0 },
1690:     { NULL, NULL, NULL }
1691: };
1692: 
1693: static const struct expr_provider_single binary_op_providers[] = {
1694:     { op_ipmatch,   "ipmatch",      subnet_parse_arg, 0 },
1695:     { op_fnmatch,   "fnmatch",      NULL,             0 },
1696:     { op_strmatch,  "strmatch",     NULL,             0 },
```

Bionic lines 1734-1763 around anchor:

```c
1734:             default:
1735:                 ap_assert(0);
1736:             }
1737:             while (prov->func) {
1738:                 int match;
1739:                 if (parms->type == AP_EXPR_FUNC_OP_UNARY)
1740:                     match = !strcmp(prov->name, parms->name);
1741:                 else
1742:                     match = !strcasecmp(prov->name, parms->name);
1743:                 if (match) {
1744:                     if ((parms->flags & AP_EXPR_FLAG_RESTRICTED)
1745:                         && prov->restricted) {
1746:                         *parms->err =
1747:                             apr_psprintf(parms->ptemp,
1748:                                          "%s%s not available in restricted context",
1749:                                          (parms->type == AP_EXPR_FUNC_STRING) ? "" : "-",
1750:                                          prov->name);
1751:                         return !OK;
1752:                     }
1753:                     *parms->func = prov->func;
1754:                     if (prov->arg_parsing_func) {
1755:                         return prov->arg_parsing_func(parms);
1756:                     }
1757:                     else {
1758:                         *parms->data = prov->name;
1759:                         return OK;
1760:                     }
1761:                 }
1762:                 prov++;
1763:             }
```

