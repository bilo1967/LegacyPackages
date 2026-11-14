# CVE-2026-7363X: Focal Digest porting audit

Experimental diagnostic only. **Not a CVE fix.**
Patch must be ported and validated as a whole; no partial hunk application.

Exact zero-fuzz dry run:

```text
checking file modules/aaa/config.m4
checking file modules/aaa/mod_auth_digest.c
Hunk #12 FAILED at 282.
Hunk #13 succeeded at 338 (offset -6 lines).
Hunk #14 succeeded at 360 (offset -6 lines).
Hunk #15 succeeded at 368 (offset -6 lines).
Hunk #16 succeeded at 394 (offset -6 lines).
Hunk #17 FAILED at 410.
Hunk #18 succeeded at 438 (offset -4 lines).
Hunk #19 succeeded at 446 (offset -4 lines).
Hunk #20 FAILED at 505.
Hunk #21 FAILED at 542.
Hunk #22 succeeded at 628 (offset -4 lines).
Hunk #23 succeeded at 682 (offset -4 lines).
Hunk #24 succeeded at 728 (offset -4 lines).
Hunk #25 succeeded at 849 (offset -4 lines).
Hunk #26 succeeded at 899 (offset -4 lines).
Hunk #27 succeeded at 920 (offset -4 lines).
Hunk #28 succeeded at 946 (offset -4 lines).
Hunk #29 succeeded at 956 (offset -4 lines).
Hunk #30 FAILED at 975.
Hunk #31 succeeded at 1066 (offset -4 lines).
Hunk #32 succeeded at 1112 (offset -4 lines).
Hunk #33 succeeded at 1122 (offset -4 lines).
Hunk #34 succeeded at 1147 (offset -4 lines).
Hunk #35 succeeded at 1156 (offset -4 lines).
Hunk #36 succeeded at 1174 (offset -4 lines).
Hunk #37 FAILED at 1208.
Hunk #38 succeeded at 1301 (offset -4 lines).
Hunk #39 succeeded at 1380 (offset -4 lines).
Hunk #40 FAILED at 1409.
Hunk #41 succeeded at 1468 (offset -4 lines).
Hunk #42 succeeded at 1476 (offset -4 lines).
Hunk #43 succeeded at 1484 (offset -4 lines).
Hunk #44 succeeded at 1494 (offset -4 lines).
Hunk #45 succeeded at 1589 (offset -4 lines).
Hunk #46 succeeded at 1617 (offset -4 lines).
Hunk #47 succeeded at 1640 (offset -4 lines).
Hunk #48 succeeded at 1740 (offset -4 lines).
Hunk #49 succeeded at 1764 (offset -4 lines).
Hunk #50 succeeded at 1772 (offset -4 lines).
Hunk #51 succeeded at 1782 (offset -4 lines).
Hunk #52 FAILED at 1797.
Hunk #53 succeeded at 1834 (offset -4 lines).
Hunk #54 FAILED at 1869.
Hunk #55 succeeded at 1953 (offset -4 lines).
9 out of 55 hunks FAILED
```

Failed mod_auth_digest.c hunks: 12, 17, 20, 21, 30, 37, 40, 52, 54

## Upstream hunk #12 (old source line 272)

```diff
@@ -272,7 +282,6 @@ static int initialize_tables(server_rec
     client_shm = NULL;
     client_rmm = NULL;
     client_lock = NULL;
-    opaque_lock = NULL;
     client_list = NULL;
 
     /*
```

Focal source nearby (line numbers are only an approximation):

```text
  250 
  251     return apr_rmm_addr_get(rmm, offset);
  252 }
  253 
  254 static apr_status_t rmm_free(apr_rmm_t *rmm, void *alloc)
  255 {
  256     apr_rmm_off_t offset = apr_rmm_offset_get(rmm, alloc);
  257 
  258     return apr_rmm_free(rmm, offset);
  259 }
  260 
  261 #if APR_HAS_SHARED_MEMORY
  262 
  263 static int initialize_tables(server_rec *s, apr_pool_t *ctx)
  264 {
  265     unsigned long idx;
  266     apr_status_t   sts;
  267 
  268     /* set up client list */
  269 
  270     /* Create the shared memory segment */
  271 
  272     /*
  273      * Create a unique filename using our pid. This information is
  274      * stashed in the global variable so the children inherit it.
  275      */
  276     client_shm_filename = ap_runtime_dir_relative(ctx, "authdigest_shm");
  277     client_shm_filename = ap_append_pid(ctx, client_shm_filename, ".");
  278 
  279     /* Use anonymous shm by default, fall back on name-based. */
  280     sts = apr_shm_create(&client_shm, shmem_size, NULL, ctx);
  281     if (APR_STATUS_IS_ENOTIMPL(sts)) {
  282         /* For a name-based segment, remove it first in case of a
  283          * previous unclean shutdown. */
  284         apr_shm_remove(client_shm_filename, ctx);
  285 
  286         /* Now create that segment */
  287         sts = apr_shm_create(&client_shm, shmem_size,
  288                             client_shm_filename, ctx);
  289     }
  290 
  291     if (APR_SUCCESS != sts) {
  292         ap_log_error(APLOG_MARK, APLOG_ERR, sts, s, APLOGNO(01762)
  293                      "Failed to create shared memory segment on file %s",
  294                      client_shm_filename);
  295         log_error_and_cleanup("failed to initialize shm", sts, s);
  296         return HTTP_INTERNAL_SERVER_ERROR;
  297     }
  298 
  299     sts = apr_rmm_init(&client_rmm,
  300                        NULL, /* no lock, we'll do the locking ourselves */
  301                        apr_shm_baseaddr_get(client_shm),
  302                        shmem_size, ctx);
  303     if (sts != APR_SUCCESS) {
  304         log_error_and_cleanup("failed to initialize rmm", sts, s);
  305         return !OK;
  306     }
  307 
  308     client_list = rmm_malloc(client_rmm, sizeof(*client_list) +
  309                                          sizeof(client_entry *) * num_buckets);
  310     if (!client_list) {
  311         log_error_and_cleanup("failed to allocate shared memory", -1, s);
  312         return !OK;
```

## Upstream hunk #17 (old source line 418)

```diff
@@ -418,21 +409,13 @@ static int initialize_module(apr_pool_t
      * last child dies. Therefore we can never clean up the old stuff,
      * creating a creeping memory leak.
      */
-    if (initialize_tables(s, p) != OK) {
-        return !OK;
-    }
-#endif  /* APR_HAS_SHARED_MEMORY */
-    return OK;
+    return initialize_tables(s, p);
 }
 
 static void initialize_child(apr_pool_t *p, server_rec *s)
 {
     apr_status_t sts;
 
-    if (!client_shm) {
-        return;
-    }
-
     /* Get access to rmm in child */
     sts = apr_rmm_attach(&client_rmm,
                          NULL,
```

Focal source nearby (line numbers are only an approximation):

```text
  396                              apr_pool_t *ptemp, server_rec *s)
  397 {
  398     /* initialize_module() will be called twice, and if it's a DSO
  399      * then all static data from the first call will be lost. Only
  400      * set up our static data on the second call. */
  401     if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
  402         return OK;
  403 
  404 #if APR_HAS_SHARED_MEMORY
  405     /* Note: this stuff is currently fixed for the lifetime of the server,
  406      * i.e. even across restarts. This means that A) any shmem-size
  407      * configuration changes are ignored, and B) certain optimizations,
  408      * such as only allocating the smallest necessary entry for each
  409      * client, can't be done. However, the alternative is a nightmare:
  410      * we can't call apr_shm_destroy on a graceful restart because there
  411      * will be children using the tables, and we also don't know when the
  412      * last child dies. Therefore we can never clean up the old stuff,
  413      * creating a creeping memory leak.
  414      */
  415     if (initialize_tables(s, p) != OK) {
  416         return !OK;
  417     }
  418     /* Call cleanup_tables on exit or restart */
  419     apr_pool_cleanup_register(p, NULL, cleanup_tables, apr_pool_cleanup_null);
  420 #endif  /* APR_HAS_SHARED_MEMORY */
  421     return OK;
  422 }
  423 
  424 static void initialize_child(apr_pool_t *p, server_rec *s)
  425 {
  426     apr_status_t sts;
  427 
  428     if (!client_shm) {
  429         return;
  430     }
  431 
  432     /* Get access to rmm in child */
  433     sts = apr_rmm_attach(&client_rmm,
  434                          NULL,
  435                          apr_shm_baseaddr_get(client_shm),
  436                          p);
  437     if (sts != APR_SUCCESS) {
  438         log_error_and_cleanup("failed to attach to rmm", sts, s);
  439         return;
  440     }
  441 
  442     sts = apr_global_mutex_child_init(&client_lock,
  443                                       apr_global_mutex_lockfile(client_lock),
  444                                       p);
  445     if (sts != APR_SUCCESS) {
  446         log_error_and_cleanup("failed to create lock (client_lock)", sts, s);
  447         return;
  448     }
  449     sts = apr_global_mutex_child_init(&opaque_lock,
  450                                       apr_global_mutex_lockfile(opaque_lock),
  451                                       p);
  452     if (sts != APR_SUCCESS) {
  453         log_error_and_cleanup("failed to create lock (opaque_lock)", sts, s);
  454         return;
  455     }
  456 }
  457 
  458 /*
```

## Upstream hunk #20 (old source line 562)

```diff
@@ -562,23 +496,10 @@ static const char *add_authn_provider(cm
 
 static const char *set_qop(cmd_parms *cmd, void *config, const char *op)
 {
-    digest_config_rec *conf = (digest_config_rec *) config;
-
-    if (!strcasecmp(op, "none")) {
-        apr_array_clear(conf->qop_list);
-        *(const char **)apr_array_push(conf->qop_list) = "none";
-        return NULL;
+    if (strcasecmp(op, "auth")) {
+        return "AuthDigestQop is deprecated: only 'auth' is supported";
     }
 
-    if (!strcasecmp(op, "auth-int")) {
-        return "AuthDigestQop auth-int is not implemented";
-    }
-    else if (ap_cstr_casecmp(op, "auth")) {
-        return apr_pstrcat(cmd->pool, "Unrecognized qop: ", op, NULL);
-    }
-
-    *(const char **)apr_array_push(conf->qop_list) = op;
-
     return NULL;
 }
 
```

Focal source nearby (line numbers are only an approximation):

```text
  540                             "Digest Authentication", newp->provider_name);
  541     }
  542 
  543     /* Add it to the list now. */
  544     if (!conf->providers) {
  545         conf->providers = newp;
  546     }
  547     else {
  548         authn_provider_list *last = conf->providers;
  549 
  550         while (last->next) {
  551             last = last->next;
  552         }
  553         last->next = newp;
  554     }
  555 
  556     return NULL;
  557 }
  558 
  559 static const char *set_qop(cmd_parms *cmd, void *config, const char *op)
  560 {
  561     digest_config_rec *conf = (digest_config_rec *) config;
  562 
  563     if (!strcasecmp(op, "none")) {
  564         apr_array_clear(conf->qop_list);
  565         *(const char **)apr_array_push(conf->qop_list) = "none";
  566         return NULL;
  567     }
  568 
  569     if (!strcasecmp(op, "auth-int")) {
  570         return "AuthDigestQop auth-int is not implemented";
  571     }
  572     else if (strcasecmp(op, "auth")) {
  573         return apr_pstrcat(cmd->pool, "Unrecognized qop: ", op, NULL);
  574     }
  575 
  576     *(const char **)apr_array_push(conf->qop_list) = op;
  577 
  578     return NULL;
  579 }
  580 
  581 static const char *set_nonce_lifetime(cmd_parms *cmd, void *config,
  582                                       const char *t)
  583 {
  584     char *endptr;
  585     long  lifetime;
  586 
  587     lifetime = strtol(t, &endptr, 10);
  588     if (endptr < (t+strlen(t)) && !apr_isspace(*endptr)) {
  589         return apr_pstrcat(cmd->pool,
  590                            "Invalid time in AuthDigestNonceLifetime: ",
  591                            t, NULL);
  592     }
  593 
  594     ((digest_config_rec *) config)->nonce_lifetime = apr_time_from_sec(lifetime);
  595     return NULL;
  596 }
  597 
  598 static const char *set_nonce_format(cmd_parms *cmd, void *config,
  599                                     const char *fmt)
  600 {
  601     return "AuthDigestNonceFormat is not implemented";
  602 }
```

## Upstream hunk #21 (old source line 599)

```diff
@@ -599,37 +520,19 @@ static const char *set_nonce_lifetime(cm
     return NULL;
 }
 
-static const char *set_nonce_format(cmd_parms *cmd, void *config,
-                                    const char *fmt)
-{
-    return "AuthDigestNonceFormat is not implemented";
-}
-
 static const char *set_nc_check(cmd_parms *cmd, void *config, int flag)
 {
-#if !APR_HAS_SHARED_MEMORY
-    if (flag) {
-        return "AuthDigestNcCheck: ERROR: nonce-count checking "
-                     "is not supported on platforms without shared-memory "
-                     "support";
-    }
-#endif
-
     ((digest_config_rec *) config)->check_nc = flag;
     return NULL;
 }
 
 static const char *set_algorithm(cmd_parms *cmd, void *config, const char *alg)
 {
-    if (!strcasecmp(alg, "MD5-sess")) {
-        return "AuthDigestAlgorithm: ERROR: algorithm `MD5-sess' "
-                "is not implemented";
-    }
-    else if (ap_cstr_casecmp(alg, "MD5")) {
-        return apr_pstrcat(cmd->pool, "Invalid algorithm in AuthDigestAlgorithm: ", alg, NULL);
+    if (strcasecmp(alg, "MD5")) {
+        return apr_pstrcat(cmd->pool, "Unsupported algorithm in AuthDigestAlgorithm: ", alg, NULL);
     }
 
-    ((digest_config_rec *) config)->algorithm = alg;
+    /* conf->algorithm remains the constant, "MD5". */
     return NULL;
 }
 
```

Focal source nearby (line numbers are only an approximation):

```text
  577 
  578     return NULL;
  579 }
  580 
  581 static const char *set_nonce_lifetime(cmd_parms *cmd, void *config,
  582                                       const char *t)
  583 {
  584     char *endptr;
  585     long  lifetime;
  586 
  587     lifetime = strtol(t, &endptr, 10);
  588     if (endptr < (t+strlen(t)) && !apr_isspace(*endptr)) {
  589         return apr_pstrcat(cmd->pool,
  590                            "Invalid time in AuthDigestNonceLifetime: ",
  591                            t, NULL);
  592     }
  593 
  594     ((digest_config_rec *) config)->nonce_lifetime = apr_time_from_sec(lifetime);
  595     return NULL;
  596 }
  597 
  598 static const char *set_nonce_format(cmd_parms *cmd, void *config,
  599                                     const char *fmt)
  600 {
  601     return "AuthDigestNonceFormat is not implemented";
  602 }
  603 
  604 static const char *set_nc_check(cmd_parms *cmd, void *config, int flag)
  605 {
  606 #if !APR_HAS_SHARED_MEMORY
  607     if (flag) {
  608         return "AuthDigestNcCheck: ERROR: nonce-count checking "
  609                      "is not supported on platforms without shared-memory "
  610                      "support";
  611     }
  612 #endif
  613 
  614     ((digest_config_rec *) config)->check_nc = flag;
  615     return NULL;
  616 }
  617 
  618 static const char *set_algorithm(cmd_parms *cmd, void *config, const char *alg)
  619 {
  620     if (!strcasecmp(alg, "MD5-sess")) {
  621         return "AuthDigestAlgorithm: ERROR: algorithm `MD5-sess' "
  622                 "is not implemented";
  623     }
  624     else if (strcasecmp(alg, "MD5")) {
  625         return apr_pstrcat(cmd->pool, "Invalid algorithm in AuthDigestAlgorithm: ", alg, NULL);
  626     }
  627 
  628     ((digest_config_rec *) config)->algorithm = alg;
  629     return NULL;
  630 }
  631 
  632 static const char *set_uri_list(cmd_parms *cmd, void *config, const char *uri)
  633 {
  634     digest_config_rec *c = (digest_config_rec *) config;
  635     if (c->uri_list) {
  636         c->uri_list[strlen(c->uri_list)-1] = '\0';
  637         c->uri_list = apr_pstrcat(cmd->pool, c->uri_list, " ", uri, "\"", NULL);
  638     }
  639     else {
```

## Upstream hunk #30 (old source line 933)

```diff
@@ -933,14 +935,12 @@ static int get_digest_rec(request_rec *r
                                  ? "Proxy-Authorization"
                                  : "Authorization");
     if (!auth_line) {
-        resp->auth_hdr_sts = NO_HEADER;
-        return !OK;
+        return NO_HEADER;
     }
 
     resp->scheme = ap_getword_white(r->pool, &auth_line);
     if (ap_cstr_casecmp(resp->scheme, "Digest")) {
-        resp->auth_hdr_sts = NOT_DIGEST;
-        return !OK;
+        return NOT_DIGEST;
     }
 
     l = strlen(auth_line);
```

Focal source nearby (line numbers are only an approximation):

```text
  911     return entry;
  912 }
  913 
  914 
  915 /*
  916  * Authorization header parser code
  917  */
  918 
  919 /* Parse the Authorization header, if it exists */
  920 static int get_digest_rec(request_rec *r, digest_header_rec *resp)
  921 {
  922     const char *auth_line;
  923     apr_size_t l;
  924     int vk = 0, vv = 0;
  925     char *key, *value;
  926 
  927     auth_line = apr_table_get(r->headers_in,
  928                              (PROXYREQ_PROXY == r->proxyreq)
  929                                  ? "Proxy-Authorization"
  930                                  : "Authorization");
  931     if (!auth_line) {
  932         resp->auth_hdr_sts = NO_HEADER;
  933         return !OK;
  934     }
  935 
  936     resp->scheme = ap_getword_white(r->pool, &auth_line);
  937     if (strcasecmp(resp->scheme, "Digest")) {
  938         resp->auth_hdr_sts = NOT_DIGEST;
  939         return !OK;
  940     }
  941 
  942     l = strlen(auth_line);
  943 
  944     key   = apr_palloc(r->pool, l+1);
  945     value = apr_palloc(r->pool, l+1);
  946 
  947     while (auth_line[0] != '\0') {
  948 
  949         /* find key */
  950 
  951         while (apr_isspace(auth_line[0])) {
  952             auth_line++;
  953         }
  954         vk = 0;
  955         while (auth_line[0] != '=' && auth_line[0] != ','
  956                && auth_line[0] != '\0' && !apr_isspace(auth_line[0])) {
  957             key[vk++] = *auth_line++;
  958         }
  959         key[vk] = '\0';
  960         while (apr_isspace(auth_line[0])) {
  961             auth_line++;
  962         }
  963 
  964         /* find value */
  965 
  966         vv = 0;
  967         if (auth_line[0] == '=') {
  968             auth_line++;
  969             while (apr_isspace(auth_line[0])) {
  970                 auth_line++;
  971             }
  972 
  973             if (auth_line[0] == '\"') {         /* quoted string */
```

## Upstream hunk #37 (old source line 1169)

```diff
@@ -1169,79 +1166,66 @@ static client_entry *gen_client(const re
  * Authorization challenge generation code (for WWW-Authenticate)
  */
 
-static const char *ltox(apr_pool_t *p, unsigned long num)
-{
-    if (num != 0) {
-        return apr_psprintf(p, "%lx", num);
-    }
-    else {
-        return "";
-    }
-}
-
-static void note_digest_auth_failure(request_rec *r,
-                                     const digest_config_rec *conf,
-                                     digest_header_rec *resp, int stale)
+/* Format a client id as the opaque sent to the client. Never called with
+ * zero: the callers check client_generate() for failure first. */
+static const char *ltox(apr_pool_t *p, client_id_t num)
+{
+    return apr_psprintf(p, "%x", num);
+}
+
+/* Generate a challenge for the client, and return the status which the
+ * caller should return for this request: HTTP_UNAUTHORIZED normally, or
+ * HTTP_SERVICE_UNAVAILABLE if the per-client state which this configuration
+ * requires could not be allocated. No challenge is sent in that case: it
+ * could only carry an opaque which identifies nothing, so the client would
+ * be unable to authenticate through it however often it retried. */
+static int note_digest_auth_failure(request_rec *r,
+                                    const digest_config_rec *conf,
+                                    digest_header_rec *resp, int stale)
 {
-    const char   *qop, *opaque, *opaque_param, *domain, *nonce;
+    const char   *qop, *opaque = NULL, *opaque_param = "", *domain, *nonce;
+    client_id_t   client_key = 0;
 
     /* Setup qop */
-    if (apr_is_empty_array(conf->qop_list)) {
-        qop = ", qop=\"auth\"";
-    }
-    else if (!ap_cstr_casecmp(*(const char **)(conf->qop_list->elts), "none")) {
-        qop = "";
-    }
-    else {
-        qop = apr_pstrcat(r->pool, ", qop=\"",
-                                   apr_array_pstrcat(r->pool, conf->qop_list, ','),
-                                   "\"",
-                                   NULL);
-    }
+    qop = ", qop=\"auth\"";
 
     /* Setup opaque */
 
     if (resp->opaque == NULL) {
         /* new client */
-        if ((conf->check_nc || conf->nonce_lifetime == 0)
-            && (resp->client = gen_client(r)) != NULL) {
-            opaque = ltox(r->pool, resp->client->key);
-        }
-        else {
-            opaque = "";                /* opaque not needed */
+        if (conf->check_nc || conf->nonce_lifetime == 0) {
+            if ((client_key = client_generate(r)) == 0) {
+                return HTTP_SERVICE_UNAVAILABLE;
+            }
+            opaque = ltox(r->pool, client_key);
         }
+        /* else no opaque is needed, and none is sent */
     }
-    else if (resp->client == NULL) {
+    else if (!client_exists(resp->opaque_num, r)) {
         /* client info was gc'd */
-        resp->client = gen_client(r);
-        if (resp->client != NULL) {
-            opaque = ltox(r->pool, resp->client->key);
-            stale = 1;
-            client_list->num_renewed++;
-        }
-        else {
-            opaque = "";                /* ??? */
+        if ((client_key = client_generate(r)) == 0) {
+            return HTTP_SERVICE_UNAVAILABLE;
         }
+        opaque = ltox(r->pool, client_key);
+        stale = 1;
+        client_note_renewed();
     }
     else {
+        /* Note that the nonce-count tracked for this client is left alone
+         * here: the client may not even see this challenge (it may have
+         * been triggered by somebody else quoting its opaque), and it is
+         * tied to the nonce it was counted for in any case. */
+        client_key = resp->opaque_num;
         opaque = resp->opaque;
-        /* we're generating a new nonce, so reset the nonce-count */
-        resp->client->nonce_count = 0;
     }
 
-    if (opaque[0]) {
+    if (opaque) {
         opaque_param = apr_pstrcat(r->pool, ", opaque=\"", opaque, "\"", NULL);
     }
-    else {
-        opaque_param = NULL;
-    }
 
     /* Setup nonce */
 
-    nonce = gen_nonce(r->pool, r->request_time, opaque, r->server, conf);
-    if (resp->client && conf->nonce_lifetime == 0) {
-        memcpy(resp->client->last_nonce, nonce, NONCE_LEN+1);
-    }
+    nonce = gen_nonce(r->pool, r->request_time, opaque, r->server, conf, ap_auth_name(r));
 
     /* setup domain attribute. We want to send this attribute wherever
      * possible so that the client won't send the Authorization header
```

Focal source nearby (line numbers are only an approximation):

```text
 1147         return NULL;
 1148     }
 1149 
 1150     apr_global_mutex_lock(opaque_lock);
 1151     op = (*opaque_cntr)++;
 1152     apr_global_mutex_unlock(opaque_lock);
 1153 
 1154     if (!(entry = add_client(op, &new_entry, r->server))) {
 1155         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01769)
 1156                       "failed to allocate client entry - ignoring client");
 1157         return NULL;
 1158     }
 1159 
 1160     return entry;
 1161 }
 1162 
 1163 
 1164 /*
 1165  * Authorization challenge generation code (for WWW-Authenticate)
 1166  */
 1167 
 1168 static const char *ltox(apr_pool_t *p, unsigned long num)
 1169 {
 1170     if (num != 0) {
 1171         return apr_psprintf(p, "%lx", num);
 1172     }
 1173     else {
 1174         return "";
 1175     }
 1176 }
 1177 
 1178 static void note_digest_auth_failure(request_rec *r,
 1179                                      const digest_config_rec *conf,
 1180                                      digest_header_rec *resp, int stale)
 1181 {
 1182     const char   *qop, *opaque, *opaque_param, *domain, *nonce;
 1183 
 1184     /* Setup qop */
 1185     if (apr_is_empty_array(conf->qop_list)) {
 1186         qop = ", qop=\"auth\"";
 1187     }
 1188     else if (!strcasecmp(*(const char **)(conf->qop_list->elts), "none")) {
 1189         qop = "";
 1190     }
 1191     else {
 1192         qop = apr_pstrcat(r->pool, ", qop=\"",
 1193                                    apr_array_pstrcat(r->pool, conf->qop_list, ','),
 1194                                    "\"",
 1195                                    NULL);
 1196     }
 1197 
 1198     /* Setup opaque */
 1199 
 1200     if (resp->opaque == NULL) {
 1201         /* new client */
 1202         if ((conf->check_nc || conf->nonce_lifetime == 0)
 1203             && (resp->client = gen_client(r)) != NULL) {
 1204             opaque = ltox(r->pool, resp->client->key);
 1205         }
 1206         else {
 1207             opaque = "";                /* opaque not needed */
 1208         }
 1209     }
```

## Upstream hunk #40 (old source line 1369)

```diff
@@ -1369,57 +1354,49 @@ static authn_status get_hash(request_rec
     return auth_result;
 }
 
-static int check_nc(const request_rec *r, const digest_header_rec *resp,
-                    const digest_config_rec *conf)
+/* Check the nonce and nonce-count of a fully verified request against the
+ * state tracked for its client, record them, and generate a new challenge
+ * if they are not acceptable.
+ *
+ * The nonce-count is counted by the client per-nonce (RFC 7616 3.4.3), so
+ * the count tracked here is tied to the nonce it was counted for: a request
+ * using a newer nonce starts a new count. Within a single nonce the count
+ * must strictly increase, but it need not increase by exactly one: the
+ * client also counts the requests it sends to URIs in the protection space
+ * which turn out not to need authentication, and this server never sees
+ * those.
+ */
+static int check_and_record_nonce(request_rec *r, digest_header_rec *resp,
+                                  const digest_config_rec *conf)
 {
     unsigned long nc;
     const char *snc = resp->nonce_count;
     char *endptr;
 
-    if (conf->check_nc && !client_shm) {
-        /* Shouldn't happen, but just in case... */
-        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01771)
-                      "cannot check nonce count without shared memory");
-        return OK;
-    }
-
-    if (!conf->check_nc || !client_shm) {
-        return OK;
-    }
-
-    if (!apr_is_empty_array(conf->qop_list) &&
-        !ap_cstr_casecmp(*(const char **)(conf->qop_list->elts), "none")) {
-        /* qop is none, client must not send a nonce count */
-        if (snc != NULL) {
-            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01772)
-                          "invalid nc %s received - no nonce count allowed when qop=none",
-                          snc);
-            return !OK;
-        }
-        /* qop is none, cannot check nonce count */
-        return OK;
+    if (!conf->check_nc && conf->nonce_lifetime != 0) {
+        return OK;              /* nothing is tracked per-client */
     }
 
     nc = strtol(snc, &endptr, 16);
     if (endptr < (snc+strlen(snc)) && !apr_isspace(*endptr)) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01773)
                       "invalid nc %s received - not a number", snc);
-        return !OK;
+        return note_digest_auth_failure(r, conf, resp, 0);
     }
 
-    if (!resp->client) {
-        return !OK;
-    }
+    switch (client_update_nonce(r, resp->opaque_num, conf, resp->nonce_time,
+                                nc, resp->nonce)) {
+    case NONCE_ACCEPTED:
+        return OK;
 
-    if (nc != resp->client->nonce_count) {
-        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01774)
-                      "Warning, possible replay attack: nonce-count "
-                      "check failed: %lu != %lu", nc,
-                      resp->client->nonce_count);
-        return !OK;
-    }
+    case NONCE_STALE:
+        /* the credentials were good, so the client can silently retry with
+         * the nonce from this challenge */
+        return note_digest_auth_failure(r, conf, resp, 1);
 
-    return OK;
+    default:
+        return note_digest_auth_failure(r, conf, resp, 0);
+    }
 }
 
 static int check_nonce(request_rec *r, digest_header_rec *resp,
```

Focal source nearby (line numbers are only an approximation):

```text
 1347 
 1348         /* Something occurred.  Stop checking. */
 1349         if (auth_result != AUTH_USER_NOT_FOUND) {
 1350             break;
 1351         }
 1352 
 1353         /* If we're not really configured for providers, stop now. */
 1354         if (!conf->providers) {
 1355            break;
 1356         }
 1357 
 1358         current_provider = current_provider->next;
 1359     } while (current_provider);
 1360 
 1361     if (auth_result == AUTH_USER_FOUND) {
 1362         *rethash = password;
 1363     }
 1364 
 1365     return auth_result;
 1366 }
 1367 
 1368 static int check_nc(const request_rec *r, const digest_header_rec *resp,
 1369                     const digest_config_rec *conf)
 1370 {
 1371     unsigned long nc;
 1372     const char *snc = resp->nonce_count;
 1373     char *endptr;
 1374 
 1375     if (conf->check_nc && !client_shm) {
 1376         /* Shouldn't happen, but just in case... */
 1377         ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01771)
 1378                       "cannot check nonce count without shared memory");
 1379         return OK;
 1380     }
 1381 
 1382     if (!conf->check_nc || !client_shm) {
 1383         return OK;
 1384     }
 1385 
 1386     if (!apr_is_empty_array(conf->qop_list) &&
 1387         !strcasecmp(*(const char **)(conf->qop_list->elts), "none")) {
 1388         /* qop is none, client must not send a nonce count */
 1389         if (snc != NULL) {
 1390             ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01772)
 1391                           "invalid nc %s received - no nonce count allowed when qop=none",
 1392                           snc);
 1393             return !OK;
 1394         }
 1395         /* qop is none, cannot check nonce count */
 1396         return OK;
 1397     }
 1398 
 1399     nc = strtol(snc, &endptr, 16);
 1400     if (endptr < (snc+strlen(snc)) && !apr_isspace(*endptr)) {
 1401         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01773)
 1402                       "invalid nc %s received - not a number", snc);
 1403         return !OK;
 1404     }
 1405 
 1406     if (!resp->client) {
 1407         return !OK;
 1408     }
 1409 
```

## Upstream hunk #52 (old source line 1784)

```diff
@@ -1784,39 +1734,17 @@ static int authenticate_digest_user(requ
         return HTTP_INTERNAL_SERVER_ERROR;
     }
 
-    if (resp->message_qop == NULL) {
-        /* old (rfc-2069) style digest */
-        if (!ap_memeq_timingsafe(old_digest(r, resp), resp->digest, MD5_DIGEST_LEN)) {
-            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01792)
-                          "user %s: password mismatch: %s", r->user,
-                          r->uri);
-            note_digest_auth_failure(r, conf, resp, 0);
-            return HTTP_UNAUTHORIZED;
-        }
+    if (resp->message_qop == NULL
+        || ap_cstr_casecmp(resp->message_qop, "auth")) {
+        /* RFC 2069-style Digest is no longer supported. */
+        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10560)
+                      "invalid or missing qop value '%s', RFC 2069 is "
+                      "no longer supported: %s", resp->message_qop, r->uri);
+        return note_digest_auth_failure(r, conf, resp, 0);
     }
     else {
-        const char *exp_digest;
-        int match = 0, idx;
-        const char **tmp = (const char **)(conf->qop_list->elts);
-        for (idx = 0; idx < conf->qop_list->nelts; idx++) {
-            if (!ap_cstr_casecmp(*tmp, resp->message_qop)) {
-                match = 1;
-                break;
-            }
-            ++tmp;
-        }
-
-        if (!match
-            && !(apr_is_empty_array(conf->qop_list)
-                 && !ap_cstr_casecmp(resp->message_qop, "auth"))) {
-            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01793)
-                          "invalid qop `%s' received: %s",
-                          resp->message_qop, r->uri);
-            note_digest_auth_failure(r, conf, resp, 0);
-            return HTTP_UNAUTHORIZED;
-        }
-
-        exp_digest = new_digest(r, resp);
+        /* RFC 2617 (or 7616)-style Digest hash calculation. */
+        const char *exp_digest = new_digest(r, resp);
         if (!exp_digest) {
             /* we failed to allocate a client struct */
             return HTTP_INTERNAL_SERVER_ERROR;
```

Focal source nearby (line numbers are only an approximation):

```text
 1762         return HTTP_UNAUTHORIZED;
 1763     }
 1764     else if (return_code == AUTH_USER_FOUND) {
 1765         /* we have a password, so continue */
 1766     }
 1767     else if (return_code == AUTH_DENIED) {
 1768         /* authentication denied in the provider before attempting a match */
 1769         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01791)
 1770                       "user `%s' in realm `%s' denied by provider: %s",
 1771                       r->user, conf->realm, r->uri);
 1772         note_digest_auth_failure(r, conf, resp, 0);
 1773         return HTTP_UNAUTHORIZED;
 1774     }
 1775     else {
 1776         /* AUTH_GENERAL_ERROR (or worse)
 1777          * We'll assume that the module has already said what its error
 1778          * was in the logs.
 1779          */
 1780         return HTTP_INTERNAL_SERVER_ERROR;
 1781     }
 1782 
 1783     if (resp->message_qop == NULL) {
 1784         /* old (rfc-2069) style digest */
 1785         if (!ap_memeq_timingsafe(old_digest(r, resp), resp->digest, MD5_DIGEST_LEN)) {
 1786             ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01792)
 1787                           "user %s: password mismatch: %s", r->user,
 1788                           r->uri);
 1789             note_digest_auth_failure(r, conf, resp, 0);
 1790             return HTTP_UNAUTHORIZED;
 1791         }
 1792     }
 1793     else {
 1794         const char *exp_digest;
 1795         int match = 0, idx;
 1796         const char **tmp = (const char **)(conf->qop_list->elts);
 1797         for (idx = 0; idx < conf->qop_list->nelts; idx++) {
 1798             if (!strcasecmp(*tmp, resp->message_qop)) {
 1799                 match = 1;
 1800                 break;
 1801             }
 1802             ++tmp;
 1803         }
 1804 
 1805         if (!match
 1806             && !(apr_is_empty_array(conf->qop_list)
 1807                  && !strcasecmp(resp->message_qop, "auth"))) {
 1808             ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01793)
 1809                           "invalid qop `%s' received: %s",
 1810                           resp->message_qop, r->uri);
 1811             note_digest_auth_failure(r, conf, resp, 0);
 1812             return HTTP_UNAUTHORIZED;
 1813         }
 1814 
 1815         exp_digest = new_digest(r, resp);
 1816         if (!exp_digest) {
 1817             /* we failed to allocate a client struct */
 1818             return HTTP_INTERNAL_SERVER_ERROR;
 1819         }
 1820         if (!ap_memeq_timingsafe(exp_digest, resp->digest, MD5_DIGEST_LEN)) {
 1821             ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01794)
 1822                           "user %s: password mismatch: %s", r->user,
 1823                           r->uri);
 1824             note_digest_auth_failure(r, conf, resp, 0);
```

## Upstream hunk #54 (old source line 1862)

```diff
@@ -1862,40 +1784,32 @@ static int add_auth_info(request_rec *r)
         return OK;
     }
 
-    /* 2069-style entity-digest is not supported (it's too hard, and
-     * there are no clients which support 2069 but not 2617). */
+    /* Don't add Authentication-Info for 401/407 responses. */
+    if (apr_table_get(r->err_headers_out,
+                      (r->proxyreq == PROXYREQ_PROXY)
+                      ? "Proxy-Authenticate" : "WWW-Authenticate")) {
+        return OK;
+    }
 
-    /* setup nextnonce
-     */
+    /* Set up nextnonce for one-time-nonces and expiring-nonce cases. */
     if (conf->nonce_lifetime > 0) {
         /* send nextnonce if current nonce will expire in less than 30 secs */
         if ((r->request_time - resp->nonce_time) > (conf->nonce_lifetime-NEXTNONCE_DELTA)) {
             nextnonce = apr_pstrcat(r->pool, ", nextnonce=\"",
                                    gen_nonce(r->pool, r->request_time,
-                                             resp->opaque, r->server, conf),
+                                             resp->opaque, r->server, conf, ap_auth_name(r)),
                                    "\"", NULL);
-            if (resp->client)
-                resp->client->nonce_count = 0;
         }
     }
-    else if (conf->nonce_lifetime == 0 && resp->client) {
+    else if (conf->nonce_lifetime == 0 && resp->opaque_num) {
         const char *nonce = gen_nonce(r->pool, 0, resp->opaque, r->server,
-                                      conf);
+                                      conf, ap_auth_name(r));
         nextnonce = apr_pstrcat(r->pool, ", nextnonce=\"", nonce, "\"", NULL);
-        memcpy(resp->client->last_nonce, nonce, NONCE_LEN+1);
     }
     /* else nonce never expires, hence no nextnonce */
 
 
-    /* do rfc-2069 digest
-     */
-    if (!apr_is_empty_array(conf->qop_list) &&
-        !ap_cstr_casecmp(*(const char **)(conf->qop_list->elts), "none")
-        && resp->message_qop == NULL) {
-        /* use only RFC-2069 format */
-        ai = nextnonce;
-    }
-    else {
+    {
         const char *resp_dig, *ha1, *a2, *ha2;
 
         /* calculate rspauth attribute
```

Focal source nearby (line numbers are only an approximation):

```text
 1840     return OK;
 1841 }
 1842 
 1843 /*
 1844  * Authorization-Info header code
 1845  */
 1846 
 1847 static int add_auth_info(request_rec *r)
 1848 {
 1849     const digest_config_rec *conf =
 1850                 (digest_config_rec *) ap_get_module_config(r->per_dir_config,
 1851                                                            &auth_digest_module);
 1852     digest_header_rec *resp =
 1853                 (digest_header_rec *) ap_get_module_config(r->request_config,
 1854                                                            &auth_digest_module);
 1855     const char *ai = NULL, *nextnonce = "";
 1856 
 1857     if (resp == NULL || !resp->needed_auth || conf == NULL) {
 1858         return OK;
 1859     }
 1860 
 1861     /* 2069-style entity-digest is not supported (it's too hard, and
 1862      * there are no clients which support 2069 but not 2617). */
 1863 
 1864     /* setup nextnonce
 1865      */
 1866     if (conf->nonce_lifetime > 0) {
 1867         /* send nextnonce if current nonce will expire in less than 30 secs */
 1868         if ((r->request_time - resp->nonce_time) > (conf->nonce_lifetime-NEXTNONCE_DELTA)) {
 1869             nextnonce = apr_pstrcat(r->pool, ", nextnonce=\"",
 1870                                    gen_nonce(r->pool, r->request_time,
 1871                                              resp->opaque, r->server, conf),
 1872                                    "\"", NULL);
 1873             if (resp->client)
 1874                 resp->client->nonce_count = 0;
 1875         }
 1876     }
 1877     else if (conf->nonce_lifetime == 0 && resp->client) {
 1878         const char *nonce = gen_nonce(r->pool, 0, resp->opaque, r->server,
 1879                                       conf);
 1880         nextnonce = apr_pstrcat(r->pool, ", nextnonce=\"", nonce, "\"", NULL);
 1881         memcpy(resp->client->last_nonce, nonce, NONCE_LEN+1);
 1882     }
 1883     /* else nonce never expires, hence no nextnonce */
 1884 
 1885 
 1886     /* do rfc-2069 digest
 1887      */
 1888     if (!apr_is_empty_array(conf->qop_list) &&
 1889         !strcasecmp(*(const char **)(conf->qop_list->elts), "none")
 1890         && resp->message_qop == NULL) {
 1891         /* use only RFC-2069 format */
 1892         ai = nextnonce;
 1893     }
 1894     else {
 1895         const char *resp_dig, *ha1, *a2, *ha2;
 1896 
 1897         /* calculate rspauth attribute
 1898          */
 1899         ha1 = resp->ha1;
 1900 
 1901         a2 = apr_pstrcat(r->pool, ":", resp->uri, NULL);
 1902         ha2 = ap_md5(r->pool, (const unsigned char *)a2);
```

