# Native Focal mod_md security-porting worklist

Diagnostic only. Neither a successful build nor this report fixes a CVE.
Focus: CVE-2025-55753, ACME renewal retry-timer overflow.

## Focal matching renewal and retry logic

### md.h: 7 matches

~~~c
   38: 
   39: #define PROTO_ACME_TLS_1        "acme-tls/1"
   40: 
   41: #define MD_TIME_LIFE_NORM           (apr_time_from_sec(100 * MD_SECS_PER_DAY))
   42: #define MD_TIME_RENEW_WINDOW_DEF    (apr_time_from_sec(33 * MD_SECS_PER_DAY))
   43: #define MD_TIME_WARN_WINDOW_DEF     (apr_time_from_sec(10 * MD_SECS_PER_DAY))
   44: 
   45: typedef enum {
   46:     MD_S_UNKNOWN = 0,               /* MD has not been analysed yet */
~~~

~~~c
   79: 
   80: typedef enum {
   81:     MD_RENEW_DEFAULT = -1,          /* default value */
   82:     MD_RENEW_MANUAL,                /* manually triggered renewal of certificate */
   83:     MD_RENEW_AUTO,                  /* automatic process performed by httpd */
   84:     MD_RENEW_ALWAYS,                /* always renewed by httpd, even if not necessary */
   85: } md_renew_mode_t;
~~~

~~~c
   96:     int renew_mode;                 /* mode of obtaining credentials */
   97:     struct md_pkey_spec_t *pkey_spec;/* specification for generating new private keys */
   98:     int must_staple;                /* certificates should set the OCSP Must Staple extension */
   99:     const md_timeslice_t *renew_window;  /* time before expiration that starts renewal */
  100:     const md_timeslice_t *warn_window;   /* time before expiration that warnings are sent out */
  101:     
  102:     const char *ca_url;             /* url of CA certificate service */
~~~

~~~c
  161: #define MD_KEY_MESSAGE          "message"
  162: #define MD_KEY_MUST_STAPLE      "must-staple"
  163: #define MD_KEY_NAME             "name"
  164: #define MD_KEY_NEXT_RUN         "next-run"
  165: #define MD_KEY_NOTIFIED         "notified"
  166: #define MD_KEY_ORDERS           "orders"
  167: #define MD_KEY_PERMANENT        "permanent"
~~~

~~~c
  173: #define MD_KEY_REGISTRATION     "registration"
  174: #define MD_KEY_RENEW            "renew"
  175: #define MD_KEY_RENEW_MODE       "renew-mode"
  176: #define MD_KEY_RENEWAL          "renewal"
  177: #define MD_KEY_RENEWING         "renewing"
  178: #define MD_KEY_RENEW_WINDOW     "renew-window"
  179: #define MD_KEY_REQUIRE_HTTPS    "require-https"
~~~

### md_acme.c: 1 matches

~~~c
  779:             "of the ACME server. You can check if you are able to contact it manually via the "
  780:             "curl command. Sometimes, the ACME server might be down for maintenance, "
  781:             "so failing to contact it is not an immediate problem. Apache will "
  782:             "continue retrying this.", acme->url);
  783:         md_result_log(result, MD_LOG_WARNING);
  784:     }
  785:     return rv;
~~~

### md_acme_authz.c: 1 matches

~~~c
  361:         
  362:         acme_id = apr_psprintf(p, "critical,DER:04:20:%s", token);
  363:         if (APR_SUCCESS != (rv = md_cert_make_tls_alpn_01(&cha_cert, authz->domain, acme_id, cha_key, 
  364:                                             apr_time_from_sec(7 * MD_SECS_PER_DAY), p))) {
  365:             md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: create tls-alpn-01 cert",
  366:                           authz->domain);
  367:             goto out;
~~~

### md_acme_drive.c: 4 matches

~~~c
  490:     d->baton = ad;
  491:     
  492:     ad->driver = d;
  493:     ad->authz_monitor_timeout = apr_time_from_sec(30);
  494:     ad->cert_poll_timeout = apr_time_from_sec(30);
  495:     ad->ca_challenges = apr_array_make(d->p, 3, sizeof(const char*));
  496:     ad->certs = apr_array_make(d->p, 5, sizeof(md_cert_t*));
  497:     
~~~

~~~c
  665:     }
  666:     
  667:     if (md_array_is_empty(ad->certs)) {
  668:         md_result_activity_printf(result, "Driving ACME protocol for renewal of %s", d->md->name);
  669:         /* The process of setting up challenges and verifying domain
  670:          * names differs between ACME versions. */
  671:         switch (MD_ACME_VERSION_MAJOR(ad->acme->version)) {
~~~

~~~c
  728:         if (APR_SUCCESS == md_reg_get_pubcert(&pub, d->reg, d->md, d->p)) {
  729:             valid_until = md_cert_get_not_after(APR_ARRAY_IDX(pub->certs, 0, const md_cert_t*));
  730:             if (valid_until > now) {            
  731:                 delay_activation = apr_time_from_sec(MD_SECS_PER_DAY);
  732:                 if (delay_activation > (valid_until - now)) {
  733:                     delay_activation = (valid_until - now);
  734:                 }
~~~

### md_acmev2_drive.c: 1 matches

~~~c
   89: }
   90: 
   91: /**************************************************************************************************/
   92: /* ACMEv2 renewal */
   93: 
   94: apr_status_t md_acmev2_drive_renew(md_acme_driver_t *ad, md_proto_driver_t *d, md_result_t *result)
   95: {
~~~

### md_crypt.c: 3 matches

~~~c
  205: static apr_time_t md_asn1_time_get(const ASN1_TIME* time)
  206: {
  207: #if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)
  208:     /* courtesy: https://stackoverflow.com/questions/10975542/asn1-time-to-time-t-conversion#11263731
  209:      * all bugs are mine */
  210:     apr_time_exp_t t;
  211:     apr_time_t ts;
~~~

~~~c
  247:     apr_time_t ts = apr_time_now();
  248:     
  249:     if (ASN1_TIME_diff(&days, &secs, NULL, time)) {
  250:         ts += apr_time_from_sec((days * MD_SECS_PER_DAY) + secs); 
  251:     }
  252:     return ts;
  253: #endif
~~~

~~~c
 1377:         rv = APR_EGENERAL; goto out;
 1378:     }
 1379:     /* validity */
 1380:     days = (int)((apr_time_sec(valid_for) + MD_SECS_PER_DAY - 1)/ MD_SECS_PER_DAY);
 1381:     if (!X509_set_notBefore(x, ASN1_TIME_set(NULL, time(NULL)))) {
 1382:         rv = APR_EGENERAL; goto out;
 1383:     }
~~~

### md_reg.c: 9 matches

~~~c
  616: {
  617:     const md_pubcert_t *pub;
  618:     const md_cert_t *cert;
  619:     md_timeperiod_t certlife, renewal;
  620:     apr_status_t rv;
  621:     
  622:     if (md->state == MD_S_INCOMPLETE) return 1;
~~~

~~~c
  627:         certlife.start = md_cert_get_not_before(cert);
  628:         certlife.end = md_cert_get_not_after(cert);
  629: 
  630:         renewal = md_timeperiod_slice_before_end(&certlife, md->renew_window);
  631:         if (md_log_is_level(p, MD_LOG_TRACE1)) {
  632:             md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, p, 
  633:                           "md[%s]: cert-life[%s] renewal[%s]", md->name, 
  634:                           md_timeperiod_print(p, &certlife),
  635:                           md_timeperiod_print(p, &renewal));
  636:         }
  637:         return md_timeperiod_has_started(&renewal, apr_time_now());
  638:     }
  639:     return 0;
  640: }
~~~

~~~c
 1074:     md_proto_driver_t *driver;
 1075:     md_result_t *result;
 1076:     apr_table_t *env;
 1077:     md_job_t *job;
 1078:     apr_status_t rv;
 1079:     
 1080:     /* For the MD,  check if something is in the STAGING area. If none is there, 
~~~

~~~c
 1102:     if (APR_SUCCESS != rv) goto out;
 1103: 
 1104:     /* If we had a job saved in STAGING, copy it over too */
 1105:     job = md_job_make(ptemp, md->name);
 1106:     if (APR_SUCCESS == md_job_load(job, reg, MD_SG_STAGING, ptemp)) {
 1107:         md_job_save(job, reg, MD_SG_TMP, NULL, ptemp);
 1108:     }
 1109:     
 1110:     /* swap */
~~~

### md_status.c: 20 matches

~~~c
  143:             rv = get_staging_cert_json(&certj, p, reg, md);
  144:             if (APR_SUCCESS != rv) goto leave;
  145:             if (certj) md_json_setj(certj, jobj, MD_KEY_CERT, NULL);
  146:             md_json_setj(jobj, mdj, MD_KEY_RENEWAL, NULL);
  147:         }
  148:         else if (APR_STATUS_IS_ENOENT(rv)) rv = APR_SUCCESS;
  149:         else goto leave;
~~~

~~~c
  177: /**************************************************************************************************/
  178: /* drive job persistence */
  179: 
  180: md_job_t *md_job_make(apr_pool_t *p, const char *name)
  181: {
  182:     md_job_t *job = apr_pcalloc(p, sizeof(*job));
  183:     job->name = apr_pstrdup(p, name);
  184:     job->p = p;
  185:     return job;
  186: }
  187: 
  188: static void md_job_from_json(md_job_t *job, md_json_t *json, apr_pool_t *p)
  189: {
  190:     const char *s;
  191:     
  192:     /* not good, this is malloced from a temp pool */
  193:     /*job->name = md_json_gets(json, MD_KEY_NAME, NULL);*/
  194:     job->finished = md_json_getb(json, MD_KEY_FINISHED, NULL);
  195:     s = md_json_dups(p, json, MD_KEY_NEXT_RUN, NULL);
  196:     if (s && *s) job->next_run = apr_date_parse_rfc(s);
  197:     s = md_json_dups(p, json, MD_KEY_LAST_RUN, NULL);
  198:     if (s && *s) job->last_run = apr_date_parse_rfc(s);
  199:     s = md_json_dups(p, json, MD_KEY_VALID_FROM, NULL);
~~~

~~~c
  205:     job->log = md_json_getj(json, MD_KEY_LOG, NULL);
  206: }
  207: 
  208: static void job_to_json(md_json_t *json, const md_job_t *job, 
  209:                         md_result_t *result, apr_pool_t *p)
  210: {
  211:     char ts[APR_RFC822_DATE_LEN];
  212: 
  213:     md_json_sets(job->name, json, MD_KEY_NAME, NULL);
  214:     md_json_setb(job->finished, json, MD_KEY_FINISHED, NULL);
  215:     if (job->next_run > 0) {
  216:         apr_rfc822_date(ts, job->next_run);
  217:         md_json_sets(ts, json, MD_KEY_NEXT_RUN, NULL);
  218:     }
  219:     if (job->last_run > 0) {
  220:         apr_rfc822_date(ts, job->last_run);
~~~

~~~c
  232:     if (job->log) md_json_setj(job->log, json, MD_KEY_LOG, NULL);
  233: }
  234: 
  235: apr_status_t md_job_load(md_job_t *job, md_reg_t *reg, 
  236:                          md_store_group_t group, apr_pool_t *p)
  237: {
  238:     md_store_t *store = md_reg_store_get(reg);
~~~

~~~c
  241:     
  242:     rv = md_store_load_json(store, group, job->name, MD_FN_JOB, &jprops, p);
  243:     if (APR_SUCCESS == rv) {
  244:         md_job_from_json(job, jprops, p);
  245:     }
  246:     return rv;
  247: }
  248: 
  249: apr_status_t md_job_save(md_job_t *job, struct md_reg_t *reg, 
  250:                          md_store_group_t group, md_result_t *result, 
  251:                          apr_pool_t *p)
  252: {
~~~

~~~c
  260:     return rv;
  261: }
  262: 
  263: void md_job_log_append(md_job_t *job, const char *type, 
  264:                        const char *status, const char *detail)
  265: {
  266:     md_json_t *entry;
~~~

~~~c
  277: }
  278: 
  279: typedef struct {
  280:     md_job_t *job;
  281:     const char *type;
  282:     md_json_t *entry;
  283:     size_t index;
~~~

~~~c
  297:     return 1;
  298: }
  299: 
  300: md_json_t *md_job_log_get_latest(md_job_t *job, const char *type)
  301: 
  302: {
  303:     log_find_ctx ctx;
~~~

~~~c
  308:     return ctx.entry;
  309: }
  310: 
  311: apr_time_t md_job_log_get_time_of_latest(md_job_t *job, const char *type)
  312: {
  313:     md_json_t *entry;
  314:     const char *s;
  315:     
  316:     entry = md_job_log_get_latest(job, type);
  317:     if (entry) {
  318:         s = md_json_gets(entry, MD_KEY_WHEN, NULL);
  319:         if (s) return apr_date_parse_rfc(s);
~~~

~~~c
  325:                            md_reg_t *reg, apr_pool_t *p)
  326: {
  327:     const md_t *md;
  328:     md_job_t job;
  329:     int i, complete, renewing, errored, ready, total;
  330:     md_json_t *json;
  331: 
~~~

~~~c
  341:                     ++renewing;
  342:                     memset(&job, 0, sizeof(job));
  343:                     job.name = md->name;
  344:                     if (APR_SUCCESS == md_job_load(&job, reg, MD_SG_STAGING, p)) {
  345:                         if (job.error_runs > 0 
  346:                             || (job.last_result && job.last_result->status != APR_SUCCESS)) {
  347:                             ++errored;
~~~

### md_status.h: 9 matches

~~~c
   41: void  md_status_take_stock(struct md_json_t **pjson, apr_array_header_t *mds, 
   42:                            struct md_reg_t *reg, apr_pool_t *p);
   43: 
   44: typedef struct md_job_t md_job_t;
   45: struct md_job_t {
   46:     const char *name;      /* Name of the MD this job is about */
   47:     apr_pool_t *p;     
   48:     apr_time_t next_run;   /* Time this job wants to be processed next */
   49:     apr_time_t last_run;   /* Time this job ran last (or 0) */
   50:     struct md_result_t *last_result; /* Result from last run */
   51:     int finished;          /* true iff the job finished successfully */
~~~

~~~c
   59:  * Create a new job instance for the given MD name. Job load/save will work
   60:  * on the MD_SG_STAGING for the name.
   61:  */
   62: md_job_t *md_job_make(apr_pool_t *p, const char *name);
   63: 
   64: /**
   65:  * Update the job from storage in <group>/job->name.
   66:  */
   67: apr_status_t md_job_load(md_job_t *job, struct md_reg_t *reg, 
   68:                          md_store_group_t group, apr_pool_t *p);
   69: 
   70: /**
   71:  * Update storage from job in <group>/job->name.
   72:  */
   73: apr_status_t md_job_save(md_job_t *job, struct md_reg_t *reg, 
   74:                          md_store_group_t group, struct md_result_t *result, 
   75:                          apr_pool_t *p);
   76: 
~~~

~~~c
   80:  * @param status        status of entry (maybe NULL)
   81:  * @param detail        description of what happened
   82:  */
   83: void md_job_log_append(md_job_t *job, const char *type, 
   84:                        const char *status, const char *detail);
   85: 
   86: /**
   87:  * Retrieve the lastest log entry of a certain type.
   88:  */
   89: md_json_t *md_job_log_get_latest(md_job_t *job, const char *type);
   90: 
   91: /**
   92:  * Get the time the latest log entry of the given type happened, or 0 if
   93:  * none is found.
   94:  */
   95: apr_time_t md_job_log_get_time_of_latest(md_job_t *job, const char *type);
   96: 
   97: #endif /* md_status_h */
~~~

### md_time.c: 16 matches

~~~c
   57: const char *md_duration_print(apr_pool_t *p, apr_interval_time_t duration)
   58: {
   59:     const char *s = "", *sep = "";
   60:     long days = (long)(apr_time_sec(duration) / MD_SECS_PER_DAY);
   61:     int rem = (int)(apr_time_sec(duration) % MD_SECS_PER_DAY);
   62:     
   63:     if (days > 0) {
   64:         s = apr_psprintf(p, "%ld days", days);
~~~

~~~c
   94: static const char *duration_format(apr_pool_t *p, apr_interval_time_t duration)
   95: {
   96:     const char *s = "0";
   97:     int units = (int)(apr_time_sec(duration) / MD_SECS_PER_DAY);
   98:     int rem = (int)(apr_time_sec(duration) % MD_SECS_PER_DAY);
   99:     
  100:     if (rem == 0) {
  101:         s = apr_psprintf(p, "%dd", units); 
  102:     }
  103:     else {
  104:         units = (int)(apr_time_sec(duration) / MD_SECS_PER_HOUR);
  105:         rem = (int)(apr_time_sec(duration) % MD_SECS_PER_HOUR);
  106:         if (rem == 0) {
  107:             s = apr_psprintf(p, "%dh", units); 
  108:         }
  109:         else {
  110:             units = (int)(apr_time_sec(duration) / 60);
  111:             rem = (int)(apr_time_sec(duration) % 60);
  112:             if (rem == 0) {
  113:                 s = apr_psprintf(p, "%dmi", units); 
  114:             }
  115:             else {
  116:                 units = (int)(apr_time_sec(duration));
  117:                 rem = (int)(apr_time_msec(duration) % 1000);
  118:                 if (rem == 0) {
  119:                     s = apr_psprintf(p, "%ds", units); 
~~~

~~~c
  235:         switch (percentage_parse(val, &percent)) {
  236:             case APR_SUCCESS:
  237:                 ts->norm = norm;
  238:                 ts->len = apr_time_from_sec((apr_time_sec(norm) * percent / 100L));
  239:                 *pts = ts;
  240:                 return NULL;
  241:             case APR_BADARG:
~~~

~~~c
  247: 
  248: const char *md_timeslice_format(const md_timeslice_t *ts, apr_pool_t *p) {
  249:     if (ts->norm > 0) {
  250:         int percent = (int)(((long)apr_time_sec(ts->len)) * 100L 
  251:                             / ((long)apr_time_sec(ts->norm))); 
  252:         return apr_psprintf(p, "%d%%", percent);
  253:     }
  254:     return duration_format(p, ts->len);
~~~

~~~c
  261:     apr_time_t duration = ts->len;
  262:     
  263:     if (ts->norm > 0) {
  264:         int percent = (int)(((long)apr_time_sec(ts->len)) * 100L 
  265:                             / ((long)apr_time_sec(ts->norm))); 
  266:         apr_time_t plen = md_timeperiod_length(period);
  267:         if (apr_time_sec(plen) > 100) {
  268:             duration = apr_time_from_sec(apr_time_sec(plen) * percent / 100);
  269:         }
  270:         else {
  271:             duration = plen * percent / 100;
~~~

### md_util.c: 4 matches

~~~c
  904:     return rv;
  905: }
  906: 
  907: /* try and retry for a while **********************************************************************/
  908: 
  909: apr_status_t md_util_try(md_util_try_fn *fn, void *baton, int ignore_errs, 
  910:                          apr_interval_time_t timeout, apr_interval_time_t start_delay, 
  911:                          apr_interval_time_t max_delay, int backoff)
  912: {
  913:     apr_status_t rv;
  914:     apr_time_t now = apr_time_now();
  915:     apr_time_t giveup = now + timeout;
  916:     apr_interval_time_t nap_duration = start_delay? start_delay : apr_time_from_msec(100);
  917:     apr_interval_time_t nap_max = max_delay? max_delay : apr_time_from_sec(10);
  918:     apr_interval_time_t left;
  919:     int i = 0;
  920:     
~~~

~~~c
  941:         }
  942:         
  943:         apr_sleep(nap_duration);
  944:         if (backoff) {
  945:             nap_duration *= 2;
  946:         } 
  947:     }
~~~

### md_util.h: 2 matches

~~~c
  189:                                   apr_pool_t *pool, const char *relation);
  190: 
  191: /**************************************************************************************************/
  192: /* retry logic */
  193: 
  194: typedef apr_status_t md_util_try_fn(void *baton, int i);
  195: 
  196: apr_status_t md_util_try(md_util_try_fn *fn, void *baton, int ignore_errs,  
  197:                          apr_interval_time_t timeout, apr_interval_time_t start_delay, 
  198:                          apr_interval_time_t max_delay, int backoff);
  199: 
  200: #endif /* md_util_h */
~~~

### mod_md.c: 2 matches

~~~c
  906:         || APR_SUCCESS != (rv = md_store_save(store, p, MD_SG_DOMAINS, md->name, 
  907:                                 MD_FN_FALLBACK_PKEY, MD_SV_PKEY, (void*)pkey, 0))
  908:         || APR_SUCCESS != (rv = md_cert_self_sign(&cert, "Apache Managed Domain Fallback", 
  909:                                     md->domains, pkey, apr_time_from_sec(14 * MD_SECS_PER_DAY), p))
  910:         || APR_SUCCESS != (rv = md_store_save(store, p, MD_SG_DOMAINS, md->name, 
  911:                                 MD_FN_FALLBACK_CERT, MD_SV_CERT, (void*)cert, 0))) {
  912:         ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10174)
~~~

~~~c
 1200:                               HTTP_MOVED_PERMANENTLY : HTTP_MOVED_TEMPORARILY);
 1201:                 }
 1202:                 else {
 1203:                     /* these should keep the method unchanged on retry */
 1204:                     status = ((MD_REQUIRE_PERMANENT == sc->assigned->require_https)? 
 1205:                               HTTP_PERMANENT_REDIRECT : HTTP_TEMPORARY_REDIRECT);
 1206:                 }
~~~

### mod_md_config.c: 2 matches

~~~c
  833:     AP_INIT_TAKE1("MDDriveMode", md_config_set_renew_mode, NULL, RSRC_CONF, 
  834:                   "deprecated, older name for MDRenewMode"),
  835:     AP_INIT_TAKE1("MDRenewMode", md_config_set_renew_mode, NULL, RSRC_CONF, 
  836:                   "Controls how renewal of Managed Domain certificates shall be handled."),
  837:     AP_INIT_TAKE_ARGV("MDomain", md_config_set_names, NULL, RSRC_CONF, 
  838:                       "A group of server names with one certificate"),
  839:     AP_INIT_RAW_ARGS(MD_CMD_MD_SECTION, md_config_sec_start, NULL, RSRC_CONF, 
~~~

~~~c
  860:     AP_INIT_TAKE1("MDStoreDir", md_config_set_store_dir, NULL, RSRC_CONF, 
  861:                   "the directory for file system storage of managed domain data."),
  862:     AP_INIT_TAKE1("MDRenewWindow", md_config_set_renew_window, NULL, RSRC_CONF, 
  863:                   "Time length for renewal before certificate expires (defaults to days)"),
  864:     AP_INIT_TAKE1("MDRequireHttps", md_config_set_require_https, NULL, RSRC_CONF, 
  865:                   "Redirect non-secure requests to the https: equivalent."),
  866:     AP_INIT_RAW_ARGS("MDNotifyCmd", md_config_set_notify_cmd, NULL, RSRC_CONF, 
~~~

### mod_md_config.h: 1 matches

~~~c
   76:     int renew_mode;                    /* mode of obtaining credentials */
   77:     int must_staple;                   /* certificates should set the OCSP Must Staple extension */
   78:     struct md_pkey_spec_t *pkey_spec;  /* specification for generating private keys */
   79:     const md_timeslice_t *renew_window; /* time before expiration that starts renewal */
   80:     const md_timeslice_t *warn_window;  /* time before expiration that warning are sent out */
   81:     
   82:     const char *ca_url;                /* url of CA certificate service */
~~~

### mod_md_drive.c: 48 matches

~~~c
   70: 
   71: typedef struct {
   72:     apr_pool_t *p;
   73:     md_job_t *job;
   74:     md_reg_t *reg;
   75:     md_result_t *last;
   76:     apr_time_t last_save;
   77: } md_job_result_ctx;
   78: 
   79: static void job_result_update(md_result_t *result, void *data)
   80: {
   81:     md_job_result_ctx *ctx = data;
   82:     apr_time_t now;
   83:     const char *msg, *sep;
   84:     
~~~

~~~c
   99:                 msg = apr_psprintf(result->p, "%s%sproblem: %s", msg, sep, result->problem);
  100:                 sep = " ";
  101:             }
  102:             md_job_log_append(ctx->job, "progress", NULL, msg);
  103: 
  104:             if (apr_time_msec(now - ctx->last_save) > 500) {
  105:                 md_job_save(ctx->job, ctx->reg, MD_SG_STAGING, result, ctx->p);
  106:                 ctx->last_save = now;
  107:             }
  108:         }
  109:     }
  110: }
  111: 
  112: static void job_result_observation_start(md_job_t *job, md_result_t *result, 
  113:                                          md_reg_t *reg, apr_pool_t *p)
  114: {
  115:     md_job_result_ctx *ctx;
  116: 
  117:     ctx = apr_pcalloc(p, sizeof(*ctx));
  118:     ctx->p = p;
~~~

~~~c
  123:     md_result_on_change(result, job_result_update, ctx);
  124: }
  125: 
  126: static void job_result_observation_end(md_job_t *job, md_result_t *result)
  127: {
  128:     (void)job;
  129:     md_result_on_change(result, NULL, NULL);
~~~

~~~c
  135:     
  136:     if (err_count > 0) {
  137:         /* back off duration, depending on the errors we encounter in a row */
  138:         delay = apr_time_from_sec(5 << (err_count - 1));
  139:         if (delay > apr_time_from_sec(60*60)) {
  140:             delay = apr_time_from_sec(60*60);
  141:         }
  142:     }
  143:     return delay;
  144: }
  145: 
  146: static apr_status_t send_notification(md_drive_ctx *dctx, md_job_t *job, const md_t *md, 
  147:                                       const char *reason, md_result_t *result, apr_pool_t *ptemp)
  148: {
  149:     const char * const *argv;
~~~

~~~c
  164:                                          "MDNotifyCmd %s failed with exit code %d.", 
  165:                                          dctx->mc->notify_cmd, exit_code);
  166:                 md_result_log(result, MD_LOG_ERR);
  167:                 md_job_log_append(job, "notify-error", result->problem, result->detail);
  168:                 goto leave;
  169:             }
  170:         }
~~~

~~~c
  185:                                      "MDMessageCmd %s failed with exit code %d.", 
  186:                                      dctx->mc->notify_cmd, exit_code);
  187:             md_result_log(result, MD_LOG_ERR);
  188:             md_job_log_append(job, "message-error", reason, result->detail);
  189:             goto leave;
  190:         }
  191:     }
~~~

~~~c
  193:     return rv;
  194: }
  195: 
  196: static void check_expiration(md_drive_ctx *dctx, md_job_t *job, const md_t *md, apr_pool_t *ptemp)
  197: {
  198:     md_timeperiod_t since_last;
  199:     
~~~

~~~c
  201:     if (!md_reg_should_warn(dctx->mc->reg, md, dctx->p)) return;
  202:     
  203:     /* Sends these out at most once per day */
  204:     since_last.start = md_job_log_get_time_of_latest(job, "message-expiring");
  205:     since_last.end = apr_time_now();
  206: 
  207:     if (md_timeperiod_length(&since_last) >= apr_time_from_sec(MD_SECS_PER_DAY)) {
  208:         ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, dctx->s, 
  209:                      "md(%s): message expiration warning", md->name);
  210:         send_notification(dctx, job, md, "expiring", NULL, ptemp);
  211:     }
  212: }
  213: 
  214: static void process_drive_job(md_drive_ctx *dctx, md_job_t *job, apr_pool_t *ptemp)
  215: {
  216:     const md_t *md;
  217:     md_result_t *result;
  218:     int error_run = 0, fatal_run = 0, save = 0;
  219:     apr_status_t rv;
  220:     
  221:     md_job_load(job, dctx->mc->reg, MD_SG_STAGING, ptemp);
  222:     /* Evaluate again on loaded value. Values will change when watchdog switches child process */
  223:     if (apr_time_now() < job->next_run) return;
  224:     
  225:     md = md_get_by_name(dctx->mc->mds, job->name);
  226:     AP_DEBUG_ASSERT(md);
~~~

~~~c
  237:     
  238:     while (md_will_renew_cert(md)) {
  239:         if (job->finished) {
  240:             job->next_run = 0;
  241:             /* Finished jobs might take a while before the results become valid.
  242:              * If that is in the future, request to run then */
  243:             if (apr_time_now() < job->valid_from) {
  244:                 job->next_run = job->valid_from;
  245:             }
  246:             else if (md_job_log_get_time_of_latest(job, "notified") == 0) {
  247:                 rv = send_notification(dctx, job, md, "renewed", result, ptemp);
  248:                 if (APR_SUCCESS == rv) {
  249:                     md_job_log_append(job, "notified", NULL, NULL);
  250:                     save = 1;
  251:                 }
  252:                 else { 
~~~

~~~c
  260:         if (!md_reg_should_renew(dctx->mc->reg, md, dctx->p)) {
  261:             ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10053) 
  262:                          "md(%s): no need to renew yet", job->name);
  263:             job->next_run = 0;
  264:             goto leave;
  265:         }
  266: 
~~~

~~~c
  271:          */
  272:         ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10052) 
  273:                      "md(%s): state=%d, driving", job->name, md->state);
  274:         md_job_log_append(job, "renewal-start", NULL, NULL);
  275:         /* observe result changes and persist them with limited frequency */
  276:         job_result_observation_start(job, result, dctx->mc->reg, ptemp);
  277:         
~~~

~~~c
  282:             ap_log_error( APLOG_MARK, APLOG_ERR, result->status, dctx->s, APLOGNO(10056) 
  283:                          "processing %s: %s", job->name, result->detail);
  284:             error_run = 1;
  285:             md_job_log_append(job, "renewal-error", result->problem, result->detail);
  286:             send_notification(dctx, job, md, "errored", result, ptemp);
  287:             goto leave;
  288:         }
~~~

### mod_md_status.c: 14 matches

~~~c
  112:                      resp, MD_KEY_SHA256_FINGERPRINT, NULL);
  113:     }
  114:     
  115:     if (md_json_has_key(mdj, MD_KEY_RENEWAL, NULL)) {
  116:         /* copy over the information we want to make public about this:
  117:          *  - when not finished, add an empty object to indicate something is going on
  118:          *  - when a certificate is staged, add the information from that */
  119:         certj = md_json_getj(mdj, MD_KEY_RENEWAL, MD_KEY_CERT, NULL);
  120:         j = certj? certj : md_json_create(r->pool);; 
  121:         md_json_setj(j, resp, MD_KEY_RENEWAL, NULL);
  122:     }
  123:     
  124:     ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "md[%s]: sending status", md->name);
~~~

~~~c
  294:     }
  295: }
  296: 
  297: static void si_val_renewal(status_ctx *ctx, md_json_t *mdj, const status_info *info)
  298: {
  299:     char buffer[HUGE_STRING_LEN];
  300:     apr_status_t rv;
~~~

~~~c
  303:     const char *s;
  304:     
  305:     (void)info;
  306:     if (!md_json_has_key(mdj, MD_KEY_RENEWAL, NULL)) {
  307:         return;
  308:     }
  309:     
  310:     finished = (int)md_json_getl(mdj, MD_KEY_RENEWAL, MD_KEY_FINISHED, NULL);
  311:     errors = (int)md_json_getl(mdj, MD_KEY_RENEWAL, MD_KEY_ERRORS, NULL);
  312:     rv = (apr_status_t)md_json_getl(mdj, MD_KEY_RENEWAL, MD_KEY_LAST, MD_KEY_STATUS, NULL);
  313:     
  314:     if (rv != APR_SUCCESS) {
  315:         s = md_json_gets(mdj, MD_KEY_RENEWAL, MD_KEY_LAST, MD_KEY_PROBLEM, NULL);
  316:         apr_brigade_printf(ctx->bb, NULL, NULL, "Error[%s]: %s", 
  317:                            apr_strerror(rv, buffer, sizeof(buffer)), s? s : "");
  318:     }
  319:     
  320:     if (finished) {
  321:         apr_brigade_puts(ctx->bb, NULL, NULL, "Finished");
  322:         if (md_json_has_key(mdj, MD_KEY_RENEWAL, MD_KEY_VALID_FROM, NULL)) {
  323:             s = md_json_gets(mdj,  MD_KEY_RENEWAL, MD_KEY_VALID_FROM, NULL);
  324:             t = apr_date_parse_rfc(s);
  325:             apr_brigade_puts(ctx->bb, NULL, NULL, (apr_time_now() >= t)?
  326:                              ", valid since: " : ", activate at: ");
~~~

~~~c
  329:         apr_brigade_puts(ctx->bb, NULL, NULL, ".");
  330:     } 
  331:     
  332:     s = md_json_gets(mdj, MD_KEY_RENEWAL, MD_KEY_LAST, MD_KEY_DETAIL, NULL);
  333:     if (s) apr_brigade_puts(ctx->bb, NULL, NULL, s);
  334:     
  335:     errors = (int)md_json_getl(mdj, MD_KEY_ERRORS, NULL);
~~~

~~~c
  337:         apr_brigade_printf(ctx->bb, NULL, NULL, ", Had %d errors.", errors);
  338:     } 
  339:     
  340:     s = md_json_gets(mdj,  MD_KEY_RENEWAL, MD_KEY_NEXT_RUN, NULL);
  341:     if (s) {
  342:         t = apr_date_parse_rfc(s);
  343:         apr_brigade_puts(ctx->bb, NULL, NULL, "Next attempt: ");
~~~

~~~c
  370:     { "Renew", MD_KEY_RENEW_MODE, si_val_renew_mode },
  371:     { "Check@", MD_KEY_SHA256_FINGERPRINT, si_val_remote_check },
  372:     { "Configuration", MD_KEY_MUST_STAPLE, si_val_props },
  373:     { "Renewal",  MD_KEY_NOTIFIED, si_val_renewal },
  374: };
  375: 
  376: static int json_iter_val(void *data, size_t index, md_json_t *json)
~~~

Total matching source lines: 144

## Jammy matching renewal and retry logic

### md.h: 12 matches

~~~c
   26: struct apr_hash_t;
   27: struct md_json_t;
   28: struct md_cert_t;
   29: struct md_job_t;
   30: struct md_pkey_t;
   31: struct md_result_t;
   32: struct md_store_t;
~~~

~~~c
   42: 
   43: #define PROTO_ACME_TLS_1        "acme-tls/1"
   44: 
   45: #define MD_TIME_LIFE_NORM           (apr_time_from_sec(100 * MD_SECS_PER_DAY))
   46: #define MD_TIME_RENEW_WINDOW_DEF    (apr_time_from_sec(33 * MD_SECS_PER_DAY))
   47: #define MD_TIME_WARN_WINDOW_DEF     (apr_time_from_sec(10 * MD_SECS_PER_DAY))
   48: #define MD_TIME_OCSP_KEEP_NORM      (apr_time_from_sec(7 * MD_SECS_PER_DAY))
   49: 
   50: #define MD_OTHER                "other"
   51: 
~~~

~~~c
   67: 
   68: typedef enum {
   69:     MD_RENEW_DEFAULT = -1,          /* default value */
   70:     MD_RENEW_MANUAL,                /* manually triggered renewal of certificate */
   71:     MD_RENEW_AUTO,                  /* automatic process performed by httpd */
   72:     MD_RENEW_ALWAYS,                /* always renewed by httpd, even if not necessary */
   73: } md_renew_mode_t;
~~~

~~~c
   79:     struct apr_array_header_t *contacts;   /* list of contact uris, e.g. mailto:xxx */
   80: 
   81:     struct md_pkeys_spec_t *pks;    /* specification for generating private keys */
   82:     md_timeslice_t *renew_window;   /* time before expiration that starts renewal */
   83:     md_timeslice_t *warn_window;    /* time before expiration that warnings are sent out */
   84:     
   85:     const char *ca_proto;           /* protocol used vs CA (e.g. ACME) */
~~~

~~~c
   94:     const char *ca_eab_hmac;        /* optional HMAC for external account binding */
   95:     const char *profile;            /* optional cert profile to order */
   96:     int profile_mandatory;          /* if profile, when given, is mandatory */
   97:     int ari_renewals;               /* if ACME ARI (RFC 9773) can trigger renewals */
   98: 
   99:     const char *state_descr;        /* description of state of NULL */
  100:     
~~~

~~~c
  121: #define MD_KEY_ACTIVITY         "activity"
  122: #define MD_KEY_AGREEMENT        "agreement"
  123: #define MD_KEY_ARI_CERT_ID      "ari-cert-id"
  124: #define MD_KEY_ARI_RENEWALS     "ari-renewals"
  125: #define MD_KEY_AUTHORIZATIONS   "authorizations"
  126: #define MD_KEY_BITS             "bits"
  127: #define MD_KEY_CA               "ca"
~~~

~~~c
  172: #define MD_KEY_MESSAGE          "message"
  173: #define MD_KEY_MUST_STAPLE      "must-staple"
  174: #define MD_KEY_NAME             "name"
  175: #define MD_KEY_NEXT_RUN         "next-run"
  176: #define MD_KEY_NOTIFIED         "notified"
  177: #define MD_KEY_NOTIFIED_RENEWED "notified-renewed"
  178: #define MD_KEY_OCSP             "ocsp"
~~~

~~~c
  190: #define MD_KEY_RENEW            "renew"
  191: #define MD_KEY_RENEW_AT         "renew-at"
  192: #define MD_KEY_RENEW_MODE       "renew-mode"
  193: #define MD_KEY_RENEWAL          "renewal"
  194: #define MD_KEY_RENEWING         "renewing"
  195: #define MD_KEY_RENEW_WINDOW     "renew-window"
  196: #define MD_KEY_REQUIRE_HTTPS    "require-https"
~~~

~~~c
  320: /**************************************************************************************************/
  321: /* notifications */
  322: 
  323: typedef apr_status_t md_job_notify_cb(struct md_job_t *job, const char *reason, 
  324:                                       struct md_result_t *result, apr_pool_t *p, void *baton);
  325: 
  326: /**************************************************************************************************/
~~~

### md_acme.c: 5 matches

~~~c
  721:         acme->api.v2.revoke_cert = md_json_dups(acme->p, json, "revokeCert", NULL);
  722:         acme->api.v2.key_change = md_json_dups(acme->p, json, "keyChange", NULL);
  723:         acme->api.v2.new_nonce = md_json_dups(acme->p, json, "newNonce", NULL);
  724:         acme->api.v2.renewal_info = md_json_dups(acme->p, json, "renewalInfo", NULL);
  725:         /* RFC 8555 only requires "directory" and "newNonce" resources.
  726:          * mod_md uses "newAccount" and "newOrder" so check for them.
  727:          * But mod_md does not use the "revokeCert" or "keyChange"
~~~

~~~c
  793:     /* TODO: maybe this should be configurable. Let's take some reasonable 
  794:      * defaults for now that protect our client */
  795:     md_http_set_response_limit(acme->http, 1024*1024);
  796:     md_http_set_timeout_default(acme->http, apr_time_from_sec(10 * 60));
  797:     md_http_set_connect_timeout_default(acme->http, apr_time_from_sec(30));
  798:     md_http_set_stalling_default(acme->http, 10, apr_time_from_sec(30));
  799:     md_http_set_ca_file(acme->http, acme->ca_file);
  800:     
  801:     md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->p, "get directory from %s", acme->url);
~~~

~~~c
  813:             "of the ACME server. You can check if you are able to contact it manually via the "
  814:             "curl command. Sometimes, the ACME server might be down for maintenance, "
  815:             "so failing to contact it is not an immediate problem. Apache will "
  816:             "continue retrying this.", acme->url);
  817:         md_result_log(result, MD_LOG_WARNING);
  818:     }
  819:     return rv;
~~~

### md_acme.h: 1 matches

~~~c
  118:             const char *key_change;
  119:             const char *revoke_cert;
  120:             const char *new_nonce;
  121:             const char *renewal_info;
  122:             struct apr_array_header_t *profiles;
  123:         } v2;
  124:     } api;
~~~

### md_acme_authz.c: 1 matches

~~~c
  374:             }
  375: 
  376:             if (APR_SUCCESS != (rv = md_cert_make_tls_alpn_01(&cha_cert, authz->domain, acme_id, cha_key,
  377:                                                               apr_time_from_sec(7 * MD_SECS_PER_DAY), p))) {
  378:                 md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: create tls-alpn-01 %s challenge cert",
  379:                               authz->domain, md_pkey_spec_name(key_spec));
  380:                 goto out;
~~~

### md_acme_drive.c: 9 matches

~~~c
  515:     d->baton = ad;
  516:     
  517:     ad->driver = d;
  518:     ad->authz_monitor_timeout = apr_time_from_sec(300);
  519:     ad->cert_poll_timeout = apr_time_from_sec(300);
  520:     ad->ca_challenges = apr_array_make(d->p, 3, sizeof(const char*));
  521:     
  522:     /* We want to obtain credentials (key+certificate) for every key spec in this MD */
~~~

~~~c
  688:     if (ad->md && ad->md->ca_effective) {
  689:         /* There was one chosen on the previous run. Do we stick to it? */
  690:         ca_effective = ad->md->ca_effective;
  691:         if (d->md->ca_urls->nelts > 1 && d->attempt >= d->retry_failover) {
  692:             /* We have more than one CA to choose from and this is the (at least)
  693:              * third attempt with the same CA. Let's switch to the next one. */
  694:             int last_idx = md_array_str_index(d->md->ca_urls, ca_effective, 0, 1);
~~~

~~~c
  897:             if (first) {
  898:                 md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, 
  899:                               "%s: delay ready_at to now+1s", d->md->name);
  900:                 md_result_delay_set(result, apr_time_now() + apr_time_from_sec(1));
  901:             }
  902:         }
  903:         else if (valid_until > now) {            
~~~

~~~c
 1152:                       "setup ACME communications");
 1153:         goto out;
 1154:     }
 1155:     if (ad->acme->version != MD_ACME_VERSION_2 || !ad->acme->api.v2.renewal_info) {
 1156:         md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p,
 1157:                       "ARI not supported by ACME CA %s", ca_effective);
 1158:         goto out;
~~~

~~~c
 1172:         if (md_cert_get_ari_cert_id(&ari_cert_id, cert, d->p) != APR_SUCCESS)
 1173:           continue;
 1174: 
 1175:         ari_url = apr_psprintf(d->p, "%s/%s", ad->acme->api.v2.renewal_info,
 1176:                                ari_cert_id);
 1177:         md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p,
 1178:                       "GET #%d ARI from %s", i, ari_url);
~~~

~~~c
 1193:         ari_expl_url = md_json_gets(json, "explanationURL", NULL);
 1194:         if (!renew_start || !renew_end) {
 1195:             md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, d->p,
 1196:                           "renewal info from CA incomplete for %s", ari_url);
 1197:             continue;
 1198:         }
 1199:         start = md_time_parse_rfc3339(renew_start);
~~~

~~~c
 1212:         }
 1213:         if (start > end) {
 1214:             md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, d->p,
 1215:                           "CA advises weird renewal between '%s' and '%s'",
 1216:                           renew_start, renew_end);
 1217:             continue;
 1218:         }
~~~

~~~c
 1223:                       ari_expl_url? ari_expl_url : "none given");
 1224:         /* select a random value between start and end */
 1225:         md_rand_bytes(&c, sizeof(c), d->p);
 1226:         start += apr_time_from_sec((apr_time_sec(end - start) * (c - 128)) / 256);
 1227:         if (!*prenew_at || (start < *prenew_at)) {
 1228:           *prenew_at = start;
 1229:           *purl = apr_pstrdup(d->p, ari_expl_url);
~~~

### md_acmev2_drive.c: 3 matches

~~~c
  145: }
  146: 
  147: /**************************************************************************************************/
  148: /* ACMEv2 renewal */
  149: 
  150: apr_status_t md_acmev2_drive_renew(md_acme_driver_t *ad, md_proto_driver_t *d, md_result_t *result)
  151: {
~~~

~~~c
  188:         goto leave;
  189:     }
  190: 
  191: retry:
  192:     if (!ad->order) {
  193:         rv = ad_setup_order(d, result, &is_new_order);
  194:         if (APR_SUCCESS != rv) goto leave;
~~~

~~~c
  200:         /* found 'invalid' domains in previous order, need to start over */
  201:         ad->order = NULL;
  202:         md_acme_order_purge(d->store, d->p, MD_SG_STAGING, d->md, d->env);
  203:         goto retry;
  204:     }
  205:     if (APR_SUCCESS != rv) goto leave;
  206:     
~~~

### md_core.c: 3 matches

~~~c
  113:         md->acme_tls_1_domains = apr_array_make(p, 5, sizeof(const char *));
  114:         md->stapling = -1;
  115:         md->profile_mandatory = -1;
  116:         md->ari_renewals = -1;
  117:         md->defn_name = "unknown";
  118:         md->defn_line_number = 0;
  119:     }
~~~

~~~c
  324:         }
  325:         if (md->profile) md_json_sets(md->profile, json, MD_KEY_PROFILE, NULL);
  326:         md_json_setb(md->profile_mandatory > 0, json, MD_KEY_PROFILE_MANDATORY, NULL);
  327:         md_json_setb(md->ari_renewals > 0, json, MD_KEY_ARI_RENEWALS, NULL);
  328:         return json;
  329:     }
  330:     return NULL;
~~~

~~~c
  395:         md->profile_mandatory = (int)md_json_getb(json, MD_KEY_PROFILE_MANDATORY, NULL);
  396:         if (md_json_has_key(json, MD_KEY_PROFILE, NULL))
  397:             md->profile = md_json_dups(p, json, MD_KEY_PROFILE, NULL);
  398:         md->ari_renewals = (int)md_json_getb(json, MD_KEY_ARI_RENEWALS, NULL);
  399:         return md;
  400:     }
  401:     return NULL;
~~~

### md_crypt.c: 3 matches

~~~c
  213: {
  214: #if OPENSSL_VERSION_NUMBER < 0x10002000L || (defined(LIBRESSL_VERSION_NUMBER) && \
  215:                                              LIBRESSL_VERSION_NUMBER < 0x3060000fL)
  216:     /* courtesy: https://stackoverflow.com/questions/10975542/asn1-time-to-time-t-conversion#11263731
  217:      * all bugs are mine */
  218:     apr_time_exp_t t;
  219:     apr_time_t ts;
~~~

~~~c
  259:     apr_time_t ts = apr_time_now();
  260:     
  261:     if (ASN1_TIME_diff(&days, &secs, NULL, time)) {
  262:         ts += apr_time_from_sec((days * MD_SECS_PER_DAY) + secs); 
  263:     }
  264:     return ts;
  265: #endif
~~~

~~~c
 1994:         rv = APR_EGENERAL; goto out;
 1995:     }
 1996:     /* validity */
 1997:     days = (int)((apr_time_sec(valid_for) + MD_SECS_PER_DAY - 1)/ MD_SECS_PER_DAY);
 1998:     if (!X509_set_notBefore(x, ASN1_TIME_set(NULL, time(NULL)))) {
 1999:         rv = APR_EGENERAL; goto out;
 2000:     }
~~~

### md_curl.c: 1 matches

~~~c
  188: 
  189: static long timeout_sec(apr_time_t timeout)
  190: {
  191:     long s = (long)apr_time_sec(timeout);
  192:     return s? s : (timeout? 1 : 0);
  193: }
  194: 
~~~

### md_event.c: 2 matches

~~~c
   60: 
   61: apr_status_t md_event_raise(const char *event, 
   62:                             const char *mdomain, 
   63:                             struct md_job_t *job, 
   64:                             struct md_result_t *result, 
   65:                             apr_pool_t *p)
   66: {
~~~

~~~c
   77: 
   78: void md_event_holler(const char *event, 
   79:                      const char *mdomain, 
   80:                      struct md_job_t *job, 
   81:                      struct md_result_t *result, 
   82:                      apr_pool_t *p)
   83: {
~~~

### md_event.h: 4 matches

~~~c
   17: #ifndef md_event_h
   18: #define md_event_h
   19: 
   20: struct md_job_t;
   21: struct md_result_t;
   22: 
   23: typedef apr_status_t md_event_cb(const char *event, 
   24:                                  const char *mdomain, 
   25:                                  void *baton,
   26:                                  struct md_job_t *job, 
   27:                                  struct md_result_t *result, 
   28:                                  apr_pool_t *p);
   29: 
~~~

~~~c
   33: 
   34: apr_status_t md_event_raise(const char *event, 
   35:                             const char *mdomain, 
   36:                             struct md_job_t *job, 
   37:                             struct md_result_t *result, 
   38:                             apr_pool_t *p);
   39: 
   40: void md_event_holler(const char *event, 
   41:                      const char *mdomain, 
   42:                      struct md_job_t *job, 
   43:                      struct md_result_t *result, 
   44:                      apr_pool_t *p);
   45: 
~~~

### md_ocsp.c: 39 matches

~~~c
   50: /* Max acceptable OCSP response size (DER-encoded responses are typically <2 KiB) */
   51: #define MD_OCSP_MAX_RESPONSE_LEN    (64 * 1024)
   52: /* Timeout for OCSP responses */
   53: #define MD_OCSP_DEFAULT_TIMEOUT apr_time_from_sec(60)
   54: /* Timeout for connecting to OCSP servers */
   55: #define MD_OCSP_CONNECT_TIMEOUT apr_time_from_sec(30)
   56: /*
   57:  * Below this throughput in bytes per second an OCSP response is regarded as
   58:  * stalled.
   59:  */
   60: #define MD_OCSP_STALLING_BYTES 10
   61: /* Maximum duration for a stalled period during an OCSP response */
   62: #define MD_OCSP_STALLING_TIME apr_time_from_sec(30)
   63: 
   64: struct md_ocsp_reg_t {
   65:     apr_pool_t *p;
~~~

~~~c
   70:     apr_hash_t *ostat_by_id;
   71:     apr_thread_mutex_t *mutex;
   72:     md_timeslice_t renew_window;
   73:     md_job_notify_cb *notify;
   74:     void *notify_ctx;
   75:     apr_time_t min_delay;
   76: };
~~~

~~~c
   83:     OCSP_CERTID *certid;
   84:     const char *responder_url;
   85:     
   86:     apr_time_t next_run;      /* when the responder shall be asked again */
   87:     int errors;               /* consecutive failed attempts */
   88: 
   89:     md_ocsp_cert_stat_t resp_stat;
~~~

~~~c
  170: 
  171: static int ostat_should_renew(md_ocsp_status_t *ostat) 
  172: {
  173:     md_timeperiod_t renewal;
  174:     
  175:     renewal = md_timeperiod_slice_before_end(&ostat->resp_valid, &ostat->reg->renew_window);
  176:     return md_timeperiod_has_started(&renewal, apr_time_now());
  177: }  
  178: 
  179: static apr_status_t ostat_set(md_ocsp_status_t *ostat, md_ocsp_cert_stat_t stat,
~~~

~~~c
  189:     ostat->resp_mtime = mtime;
  190:     
  191:     ostat->errors = 0;
  192:     ostat->next_run = md_timeperiod_slice_before_end(
  193:         &ostat->resp_valid, &ostat->reg->renew_window).start;
  194:     
  195: cleanup:
~~~

~~~c
  429:     }
  430:     /* We have a response */
  431:     if (ostat_should_renew(ostat)) {
  432:         /* But it is up for renewal. A watchdog should be busy with
  433:          * retrieving a new one. In case of outages, this might take
  434:          * a while, however. Pace the frequency of checks with the
  435:          * urgency of a new response based on the remaining time. */
  436:         long secs = (long)apr_time_sec(md_timeperiod_remaining(&ostat->resp_valid, apr_time_now()));
  437:         apr_time_t waiting_time; 
  438:         
  439:         /* every hour, every minute, every second */
  440:         waiting_time = ((secs >= MD_SECS_PER_DAY)?
  441:                         apr_time_from_sec(60 * 60) : ((secs >= 60)? 
  442:                         apr_time_from_sec(60) : apr_time_from_sec(1)));
  443:         if ((apr_time_now() - ostat->resp_last_check) >= waiting_time) {
  444:             ostat->resp_last_check = apr_time_now();
  445:             ocsp_status_refresh(ostat, p);
~~~

~~~c
  592:     apr_pool_t *p;
  593:     md_ocsp_status_t *ostat;
  594:     md_result_t *result;
  595:     md_job_t *job;
  596: } md_ocsp_update_t;
  597: 
  598: static apr_status_t ostat_on_resp(const md_http_response_t *resp, void *baton)
~~~

~~~c
  713:     else {
  714:         /* nextUpdate not set; default to 12 hours.
  715:          * Refresh attempts will be started some time earlier. */
  716:         valid.end = valid.start + apr_time_from_sec(MD_SECS_PER_DAY / 2);
  717:     }
  718:     
  719:     /* First, update the instance with a copy */
~~~

~~~c
  748:     md_ocsp_status_t *ostat = update->ostat;
  749: 
  750:     (void)req;
  751:     md_job_end_run(update->job, update->result);
  752:     if (APR_SUCCESS != status) {
  753:         ++ostat->errors;
  754:         ostat->next_run = apr_time_now() + md_job_delay_on_errors(update->job, ostat->errors, NULL);
  755:         md_result_printf(update->result, status, "OCSP status update failed (%d. time)",  
  756:                          ostat->errors);
  757:         md_result_log(update->result, MD_LOG_DEBUG);
  758:         md_job_log_append(update->job, "ocsp-error", 
  759:                           update->result->problem, update->result->detail);
  760:         md_event_holler("ocsp-errored", update->job->mdomain, update->job, update->result, update->p);
  761:         goto cleanup;
~~~

~~~c
  763:     md_event_holler("ocsp-renewed", update->job->mdomain, update->job, update->result, update->p);
  764: 
  765: cleanup:
  766:     md_job_save(update->job, update->result, update->p);
  767:     ostat_req_cleanup(ostat);
  768:     return APR_SUCCESS;
  769: }
~~~

~~~c
  829:             ostat = update->ostat;
  830:             
  831:             update->job = md_ocsp_job_make(ctx->reg, ostat->md_name, update->p);
  832:             md_job_load(update->job);
  833:             md_job_start_run(update->job, update->result, ctx->reg->store);
  834:              
  835:             if (!ostat->ocsp_req) {
  836:                 rv = ocsp_req_make(&ostat->ocsp_req, ostat->certid);
~~~

~~~c
  868:     
  869:     (void)key;
  870:     (void)klen;
  871:     if (ostat->next_run <= ctx->time) {
  872:         update = apr_pcalloc(ctx->ptemp, sizeof(*update));
  873:         update->p = ctx->ptemp;
  874:         update->ostat = ostat;
~~~

### md_ocsp.h: 3 matches

~~~c
   18: #define md_ocsp_h
   19: 
   20: struct md_data_t;
   21: struct md_job_t;
   22: struct md_json_t;
   23: struct md_result_t;
   24: struct md_store_t;
~~~

~~~c
   58: 
   59: apr_size_t md_ocsp_count(md_ocsp_reg_t *reg);
   60: 
   61: void md_ocsp_renew(md_ocsp_reg_t *reg, apr_pool_t *p, apr_pool_t *ptemp, apr_time_t *pnext_run);
   62: 
   63: apr_status_t md_ocsp_remove_responses_older_than(md_ocsp_reg_t *reg, apr_pool_t *p, 
   64:                                                  apr_time_t timestamp);
~~~

~~~c
   66: void md_ocsp_get_summary(struct md_json_t **pjson, md_ocsp_reg_t *reg, apr_pool_t *p);
   67: void md_ocsp_get_status_all(struct md_json_t **pjson, md_ocsp_reg_t *reg, apr_pool_t *p);
   68: 
   69: struct md_job_t *md_ocsp_job_make(md_ocsp_reg_t *ocsp, const char *mdomain, apr_pool_t *p);
   70: 
   71: #endif /* md_ocsp_h */
~~~

### md_reg.c: 19 matches

~~~c
   51:     int domains_frozen;
   52:     md_timeslice_t *renew_window;
   53:     md_timeslice_t *warn_window;
   54:     md_job_notify_cb *notify;
   55:     void *notify_ctx;
   56:     apr_time_t min_delay;
   57:     int retry_failover;
   58:     int use_store_locks;
   59:     apr_time_t lock_wait_timeout;
   60: };
~~~

~~~c
   97: 
   98: apr_status_t md_reg_create(md_reg_t **preg, apr_pool_t *p, struct md_store_t *store,
   99:                            const char *proxy_url, const char *ca_file,
  100:                            apr_time_t min_delay, int retry_failover,
  101:                            int use_store_locks, apr_time_t lock_wait_timeout)
  102: {
  103:     md_reg_t *reg;
~~~

~~~c
  114:     reg->ca_file = (ca_file && apr_cstr_casecmp("none", ca_file))?
  115:                     apr_pstrdup(p, ca_file) : NULL;
  116:     reg->min_delay = min_delay;
  117:     reg->retry_failover = retry_failover;
  118:     reg->use_store_locks = use_store_locks;
  119:     reg->lock_wait_timeout = lock_wait_timeout;
  120: 
~~~

~~~c
  687: {
  688:     const md_pubcert_t *pub;
  689:     const md_cert_t *cert;
  690:     md_timeperiod_t certlife, renewal;
  691:     int i;
  692:     apr_time_t renew_at = 0, now = apr_time_now();
  693:     apr_status_t rv;
~~~

~~~c
  706:             certlife.start = md_cert_get_not_before(cert);
  707:             certlife.end = md_cert_get_not_after(cert);
  708: 
  709:             renewal = md_timeperiod_slice_before_end(&certlife, md->renew_window);
  710:             if (md_log_is_level(p, MD_LOG_TRACE1)) {
  711:                 md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, p,
  712:                               "md[%s]: certificate(%d) valid[%s] renewal[%s]", 
  713:                               md->name, i,  
  714:                               md_timeperiod_print(p, &certlife),
  715:                               md_timeperiod_print(p, &renewal));
  716:             }
  717:             
  718:             if (renew_at == 0 || renewal.start < renew_at) {
  719:                 renew_at = renewal.start;
  720:             }
  721:         }
  722:     }
~~~

~~~c
 1006:             && md_array_str_eq(md->acme_tls_1_domains, old->acme_tls_1_domains, 0)
 1007:             && !MD_VAL_UPDATE(md, old, stapling)
 1008:             && !MD_VAL_UPDATE(md, old, profile_mandatory)
 1009:             && !MD_VAL_UPDATE(md, old, ari_renewals)
 1010:             && md_array_str_eq(md->contacts, old->contacts, 0)
 1011:             && md_array_str_eq(md->cert_files, old->cert_files, 0)
 1012:             && md_array_str_eq(md->pkey_files, old->pkey_files, 0)
~~~

~~~c
 1192:         md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "%s: run staging", md->name);
 1193:         driver->reset = reset;
 1194:         driver->attempt = attempt;
 1195:         driver->retry_failover = reg->retry_failover;
 1196:         rv = driver->proto->renew(driver, result);
 1197:     }
 1198:     md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "%s: staging done", md->name);
~~~

~~~c
 1260:     md_proto_driver_t *driver;
 1261:     md_result_t *result;
 1262:     apr_table_t *env;
 1263:     md_job_t *job;
 1264:     apr_status_t rv;
 1265:     
 1266:     /* For the MD,  check if something is in the STAGING area. If none is there, 
~~~

~~~c
 1289: 
 1290:     /* If we had a job saved in STAGING, copy it over too */
 1291:     job = md_reg_job_make(reg, md->name, ptemp);
 1292:     if (APR_SUCCESS == md_job_load(job)) {
 1293:         md_job_set_group(job, MD_SG_TMP);
 1294:         md_job_save(job, NULL, ptemp);
 1295:     }
 1296:     
 1297:     /* swap */
~~~

~~~c
 1306:     md_store_purge(reg->store, p, MD_SG_CHALLENGES, md->name);
 1307:     md_result_set(result, APR_SUCCESS, "new certificate successfully saved in domains");
 1308:     md_event_holler("installed", md->name, job, result, ptemp);
 1309:     if (job->dirty) md_job_save(job, result, ptemp);
 1310:     
 1311: out:
 1312:     if (!APR_STATUS_IS_ENOENT(rv)) {
~~~

~~~c
 1401:     *reg->warn_window = *warn_window;
 1402: }
 1403: 
 1404: md_job_t *md_reg_job_make(md_reg_t *reg, const char *mdomain, apr_pool_t *p)
 1405: {
 1406:     return md_job_make(p, reg->store, MD_SG_STAGING, mdomain, reg->min_delay);
 1407: }
 1408: 
 1409: static int get_cert_count(const md_t *md)
~~~

### md_reg.h: 4 matches

~~~c
   45:  */
   46: apr_status_t md_reg_create(md_reg_t **preg, apr_pool_t *pm, md_store_t *store,
   47:                            const char *proxy_url, const char *ca_file,
   48:                            apr_time_t min_delay, int retry_failover,
   49:                            int use_store_locks, apr_time_t lock_wait_timeout);
   50: 
   51: md_store_t *md_reg_store_get(md_reg_t *reg);
~~~

~~~c
  183:  */
  184: apr_time_t md_reg_renew_at(md_reg_t *reg, const md_t *md, apr_pool_t *p);
  185: 
  186: /* Check ACME Renewal Info, if available, for the CA recommended time
  187:  * (and optional reason URL) for certificate renewal.
  188:  * Returns 0 if not availble.
  189:  */
~~~

~~~c
  231:     int can_https;
  232:     int reset;
  233:     int attempt;
  234:     int retry_failover;
  235:     apr_interval_time_t activation_delay;
  236: };
  237: 
~~~

~~~c
  301: void md_reg_set_renew_window_default(md_reg_t *reg, md_timeslice_t *renew_window);
  302: void md_reg_set_warn_window_default(md_reg_t *reg, md_timeslice_t *warn_window);
  303: 
  304: struct md_job_t *md_reg_job_make(md_reg_t *reg, const char *mdomain, apr_pool_t *p);
  305: 
  306: /**
  307:  * Acquire a cooperative, global lock on registry modifications. Will
~~~

### md_status.c: 45 matches

~~~c
  137:         else if (!APR_STATUS_IS_ENOENT(rv)) goto leave;
  138:         rv = APR_SUCCESS;
  139:         if (APR_SUCCESS == job_loadj(&jobj, MD_SG_OCSP, md->name, reg, with_logs, p)) {
  140:             md_json_setj(jobj, certj, MD_KEY_OCSP, MD_KEY_RENEWAL, NULL);
  141:         }
  142:     }
  143: 
~~~

~~~c
  269:             if (APR_SUCCESS == get_staging_certs_json(&certsj, md, reg, p)) {
  270:                 md_json_setj(certsj, jobj, MD_KEY_CERT, NULL);
  271:             }
  272:             md_json_setj(jobj, mdj, MD_KEY_RENEWAL, NULL);
  273:         }
  

--- truncated source audit ---

@@ -143,6 +163,11 @@ void md_http_set_ca_file(md_http_t *http
@@ -177,7 +202,6 @@ static apr_status_t req_set_body_data(md
@@ -211,17 +235,20 @@ static apr_status_t req_create(md_http_r
@@ -308,10 +335,16 @@ apr_status_t md_http_POSTd_create(md_htt
+++ b/modules/md/md_http.h
@@ -65,6 +65,7 @@ struct md_http_request_t {
@@ -87,6 +88,13 @@ apr_status_t md_http_create(md_http_t **
@@ -118,6 +126,12 @@ void md_http_set_stalling(md_http_reques
+++ b/modules/md/md_json.c
@@ -176,7 +176,7 @@ static apr_status_t jselect_add(json_t *
@@ -202,7 +202,7 @@ static apr_status_t jselect_insert(json_
@@ -1186,14 +1186,18 @@ apr_status_t md_json_read_http(md_json_t
@@ -1264,7 +1268,7 @@ apr_status_t md_json_set_timeperiod(cons
+++ b/modules/md/md_log.h
@@ -38,6 +38,10 @@ typedef enum {
+++ b/modules/md/md_ocsp.c
@@ -32,13 +32,6 @@
@@ -65,6 +58,7 @@ struct md_ocsp_reg_t {
@@ -196,6 +190,7 @@ static apr_status_t ostat_from_json(md_o
@@ -279,7 +274,8 @@ static apr_status_t ocsp_reg_cleanup(voi
@@ -296,6 +292,7 @@ apr_status_t md_ocsp_reg_make(md_ocsp_re
@@ -338,7 +335,7 @@ apr_status_t md_ocsp_prime(md_ocsp_reg_t
@@ -449,7 +446,7 @@ static void ocsp_get_meta(md_ocsp_cert_s
@@ -535,7 +532,7 @@ static const char *certid_summary(const
@@ -560,7 +557,9 @@ static const char *single_resp_summary(O
@@ -640,7 +639,7 @@ static apr_status_t ostat_on_resp(const
@@ -650,7 +649,7 @@ static apr_status_t ostat_on_resp(const
@@ -680,12 +679,6 @@ static apr_status_t ostat_on_resp(const
@@ -700,7 +693,14 @@ static apr_status_t ostat_on_resp(const
@@ -837,8 +837,8 @@ static apr_status_t next_todo(md_http_re
@@ -1056,5 +1056,5 @@ void md_ocsp_get_status_all(md_json_t **
+++ b/modules/md/md_ocsp.h
@@ -38,7 +38,8 @@ typedef struct md_ocsp_reg_t md_ocsp_reg
+++ b/modules/md/md_reg.c
@@ -31,6 +31,7 @@
@@ -52,6 +53,10 @@ struct md_reg_t {
@@ -75,11 +80,25 @@ static apr_status_t load_props(md_reg_t
@@ -92,8 +111,12 @@ apr_status_t md_reg_create(md_reg_t **pr
@@ -163,12 +186,17 @@ static apr_status_t check_values(md_reg_
@@ -204,11 +232,21 @@ static apr_status_t state_init(md_reg_t
@@ -243,7 +281,7 @@ static apr_status_t state_init(md_reg_t
@@ -444,7 +482,8 @@ static apr_status_t p_md_update(void *ba
@@ -650,13 +689,18 @@ apr_time_t md_reg_renew_at(md_reg_t *reg
@@ -664,7 +708,7 @@ apr_time_t md_reg_renew_at(md_reg_t *reg
@@ -672,7 +716,7 @@ apr_time_t md_reg_renew_at(md_reg_t *reg
@@ -836,12 +880,24 @@ apr_status_t md_reg_sync_start(md_reg_t
@@ -896,13 +952,23 @@ apr_status_t md_reg_sync_finish(md_reg_t
@@ -917,13 +983,16 @@ apr_status_t md_reg_sync_finish(md_reg_t
@@ -936,6 +1005,8 @@ apr_status_t md_reg_sync_finish(md_reg_t
@@ -1101,8 +1172,9 @@ apr_status_t md_reg_test_init(md_reg_t *
@@ -1112,12 +1184,15 @@ static apr_status_t run_renew(void *bato
@@ -1125,9 +1200,57 @@ static apr_status_t run_renew(void *bato
@@ -1152,7 +1275,7 @@ static apr_status_t run_load_staging(voi
@@ -1199,6 +1322,54 @@ apr_status_t md_reg_load_staging(md_reg_
@@ -1232,5 +1403,40 @@ void md_reg_set_warn_window_default(md_r
+++ b/modules/md/md_reg.h
@@ -23,6 +23,7 @@ struct md_pkey_t;
@@ -34,9 +35,18 @@ typedef struct md_reg_t md_reg_t;
@@ -173,6 +183,14 @@ int md_reg_should_renew(md_reg_t *reg, c
@@ -212,6 +230,8 @@ struct md_proto_driver_t {
@@ -220,6 +240,9 @@ typedef apr_status_t md_proto_renew_cb(m
@@ -227,6 +250,8 @@ struct md_proto_t {
@@ -240,11 +265,17 @@ apr_status_t md_reg_test_init(md_reg_t *
@@ -259,9 +290,42 @@ apr_status_t md_reg_renew(md_reg_t *reg,
+++ b/modules/md/md_status.c
@@ -47,12 +47,21 @@ static apr_status_t status_get_cert_json
@@ -111,9 +120,14 @@ static apr_status_t status_get_cert_json
@@ -126,6 +140,7 @@ static apr_status_t status_get_cert_json
@@ -206,7 +221,7 @@ static apr_status_t status_get_md_json(m
@@ -236,20 +251,28 @@ static apr_status_t status_get_md_json(m
@@ -286,7 +309,8 @@ apr_status_t md_status_get_json(md_json_
@@ -294,6 +318,7 @@ md_job_t *md_job_make(apr_pool_t *p, md_
@@ -587,10 +612,16 @@ apr_time_t md_job_delay_on_errors(md_job
+++ b/modules/md/md_status.h
@@ -68,6 +68,7 @@ struct md_job_t {
@@ -75,7 +76,8 @@ struct md_job_t {
+++ b/modules/md/md_store.c
@@ -260,7 +260,7 @@ static const char *pk_filename(const cha
@@ -374,3 +374,12 @@ apr_status_t md_store_md_iter(md_store_m
+++ b/modules/md/md_store.h
@@ -204,7 +204,23 @@ apr_status_t md_store_iter_names(md_stor
@@ -303,6 +319,8 @@ typedef apr_time_t md_store_get_modified
@@ -317,6 +335,8 @@ struct md_store_t {
+++ b/modules/md/md_store_fs.c
@@ -39,6 +39,7 @@
@@ -60,6 +61,8 @@ struct md_store_fs_t {
@@ -101,6 +104,9 @@ static int fs_is_newer(md_store_t *store
@@ -240,8 +246,8 @@ static apr_status_t read_store_file(md_s
@@ -269,6 +275,15 @@ static apr_status_t setup_store_file(voi
@@ -296,7 +311,9 @@ apr_status_t md_store_fs_init(md_store_t
@@ -521,7 +538,8 @@ static apr_status_t mk_group_dir(const c
@@ -1093,3 +1111,67 @@ static apr_status_t fs_rename(md_store_t
+++ b/modules/md/md_time.c
@@ -323,3 +323,70 @@ md_timeperiod_t md_timeperiod_common(con
+++ b/modules/md/md_time.h
@@ -74,4 +74,7 @@ const char *md_timeslice_format(const md
+++ b/modules/md/md_util.c
@@ -256,7 +256,7 @@ int md_array_str_index(const apr_array_h
@@ -278,7 +278,7 @@ int md_array_str_eq(const struct apr_arr
@@ -325,7 +325,7 @@ apr_array_header_t *md_array_str_remove(
@@ -398,6 +398,16 @@ apr_status_t md_util_is_file(const char
@@ -849,10 +859,10 @@ int md_dns_matches(const char *pattern,
@@ -906,6 +916,19 @@ int md_dns_domains_match(const apr_array
@@ -1003,8 +1026,8 @@ apr_status_t md_util_abs_http_uri_check(
@@ -1058,32 +1081,24 @@ apr_status_t md_util_try(md_util_try_fn
@@ -1494,7 +1509,7 @@ static int find_url(void *baton, const c
+++ b/modules/md/md_util.h
@@ -20,6 +20,16 @@
@@ -133,7 +143,7 @@ int md_array_str_add_missing(struct apr_
@@ -174,6 +184,11 @@ struct apr_array_header_t *md_dns_make_m
@@ -189,6 +204,7 @@ apr_status_t md_util_path_merge(const ch
+++ b/modules/md/md_version.h
@@ -27,7 +27,7 @@
@@ -35,8 +35,8 @@
+++ b/modules/md/mod_md.c
@@ -98,7 +98,7 @@ static void log_print(const char *file,
@@ -183,7 +183,7 @@ static apr_status_t notify(md_job_t *job
@@ -202,7 +202,7 @@ static apr_status_t notify(md_job_t *job
@@ -313,8 +313,8 @@ static void merge_srv_config(md_t *md, m
@@ -331,7 +331,8 @@ static void merge_srv_config(md_t *md, m
@@ -363,6 +364,15 @@ static void merge_srv_config(md_t *md, m
@@ -377,12 +387,12 @@ static apr_status_t check_coverage(md_t
@@ -586,18 +596,30 @@ static apr_status_t link_md_to_servers(m
@@ -670,17 +692,19 @@ static apr_status_t merge_mds_with_conf(
@@ -705,7 +729,7 @@ static apr_status_t merge_mds_with_conf(
@@ -713,27 +737,6 @@ static apr_status_t merge_mds_with_conf(
@@ -886,16 +889,22 @@ static apr_status_t md_post_config_befor
@@ -929,14 +938,25 @@ static apr_status_t md_post_config_befor
@@ -1167,7 +1187,7 @@ static apr_status_t get_certificates(ser
@@ -1247,7 +1267,7 @@ static int md_add_cert_files(server_rec
@@ -1276,55 +1296,95 @@ static int md_add_fallback_cert_files(se
@@ -1359,6 +1419,15 @@ static int md_http_challenge_pr(request_
@@ -1496,7 +1565,7 @@ static void md_hooks(apr_pool_t *pool)
+++ b/modules/md/mod_md.dsp
@@ -205,6 +205,10 @@ SOURCE=./md_store_fs.c
+++ b/modules/md/mod_md.mak
@@ -80,6 +80,7 @@ CLEAN :
@@ -163,6 +164,7 @@ LINK32_OBJS= \
@@ -239,6 +241,7 @@ CLEAN :
@@ -322,6 +325,7 @@ LINK32_OBJS= \
@@ -565,6 +569,11 @@ SOURCE=./md_store_fs.c
+++ b/modules/md/mod_md_config.c
@@ -26,6 +26,7 @@
@@ -83,6 +84,13 @@ static md_mod_conf_t defmc = {
@@ -106,15 +114,19 @@ static md_srv_conf_t defconf = {
@@ -160,15 +172,19 @@ static void srv_conf_props_clear(md_srv_
@@ -180,15 +196,19 @@ static void srv_conf_props_copy(md_srv_c
@@ -200,7 +220,7 @@ static void srv_conf_props_apply(md_t *m
@@ -211,7 +231,11 @@ static void srv_conf_props_apply(md_t *m
@@ -246,7 +270,8 @@ static void *md_config_merge(apr_pool_t
@@ -254,8 +279,11 @@ static void *md_config_merge(apr_pool_t
@@ -269,7 +297,7 @@ void *md_config_merge_svr(apr_pool_t *po
@@ -314,10 +342,10 @@ static const char *md_conf_check_locatio
@@ -337,11 +365,11 @@ static void add_domain_name(apr_array_he
@@ -474,19 +502,29 @@ static const char *md_config_set_names(c
@@ -536,13 +574,13 @@ static const char *md_config_set_renew_m
@@ -556,6 +594,31 @@ static const char *md_config_set_renew_m
@@ -592,6 +655,18 @@ static const char *md_config_set_staple_
@@ -602,6 +677,127 @@ static const char *md_config_set_base_se
@@ -611,13 +807,13 @@ static const char *md_config_set_require
@@ -802,7 +998,7 @@ static const char *md_config_set_pkeys(c
@@ -827,7 +1023,7 @@ static const char *md_config_set_pkeys(c
@@ -889,11 +1085,35 @@ static const char *md_config_set_dns01_c
@@ -1039,7 +1259,7 @@ static const char *md_config_set_eab(cmd
@@ -1089,8 +1309,8 @@ leave:
@@ -1138,7 +1358,9 @@ const command_rec md_cmds[] = {
@@ -1166,7 +1388,24 @@ const command_rec md_cmds[] = {
@@ -1225,8 +1464,6 @@ md_srv_conf_t *md_config_cget(conn_rec *
@@ -1239,6 +1476,8 @@ const char *md_config_gets(const md_srv_
@@ -1259,6 +1498,10 @@ int md_config_geti(const md_srv_conf_t *
+++ b/modules/md/mod_md_config.h
@@ -24,7 +24,6 @@ struct md_ocsp_reg_t;
@@ -40,8 +39,16 @@ typedef enum {
@@ -71,6 +78,13 @@ struct md_mod_conf_t {
@@ -86,16 +100,21 @@ typedef struct md_srv_conf_t {
+++ b/modules/md/mod_md_drive.c
@@ -100,22 +100,80 @@ static void process_drive_job(md_renew_c
@@ -125,7 +183,11 @@ static void process_drive_job(md_renew_c
@@ -154,7 +216,7 @@ static void process_drive_job(md_renew_c
@@ -180,10 +242,13 @@ int md_will_renew_cert(const md_t *md)
@@ -211,7 +276,7 @@ static apr_status_t run_watchdog(int sta
@@ -338,7 +403,7 @@ apr_status_t md_renew_start_watching(md_
+++ b/modules/md/mod_md_status.c
@@ -13,7 +13,7 @@
@@ -55,6 +55,7 @@
@@ -66,13 +67,13 @@ int md_http_cert_status(request_rec *r)
@@ -84,7 +85,7 @@ int md_http_cert_status(request_rec *r)
@@ -94,7 +95,7 @@ int md_http_cert_status(request_rec *r)
@@ -124,23 +125,23 @@ int md_http_cert_status(request_rec *r)
@@ -151,10 +152,12 @@ typedef struct {
@@ -179,13 +182,19 @@ static void si_val_status(status_ctx *ct
@@ -195,19 +204,28 @@ static void si_val_url(status_ctx *ctx,
@@ -216,14 +234,21 @@ static void print_date(apr_bucket_brigad
@@ -231,7 +256,7 @@ static void print_time(apr_bucket_brigad
@@ -241,25 +266,32 @@ static void print_time(apr_bucket_brigad
@@ -267,50 +299,115 @@ static void si_val_valid_time(status_ctx
@@ -324,83 +421,139 @@ static int count_certs(void *baton, cons
@@ -408,13 +561,33 @@ static int cert_check_iter(void *baton,
@@ -423,7 +596,14 @@ static void si_val_remote_check(status_c
@@ -431,24 +611,43 @@ static void si_val_stapling(status_ctx *
@@ -460,13 +659,27 @@ static void add_json_val(status_ctx *ctx
@@ -475,7 +688,14 @@ static void add_status_cell(status_ctx *
@@ -484,24 +704,33 @@ static const status_info status_infos[]
@@ -514,96 +743,121 @@ int md_domains_status_hook(request_rec *
@@ -611,53 +865,65 @@ int md_ocsp_status_hook(request_rec *r,
@@ -687,7 +953,7 @@ int md_status_handler(request_rec *r)
@@ -695,7 +961,7 @@ int md_status_handler(request_rec *r)
@@ -706,12 +972,12 @@ int md_status_handler(request_rec *r)
~~~

## CVE-2025-55753-3.patch: affected hunks

~~~text
+++ b/modules/md/md_version.h
@@ -27,7 +27,7 @@
@@ -35,7 +35,7 @@
+++ b/modules/md/mod_md_config.c
@@ -282,6 +282,7 @@ static void *md_config_merge(apr_pool_t *pool, void *basev, void *addv)
+++ b/modules/md/mod_md_ocsp.c
@@ -61,8 +61,18 @@ int md_ocsp_prime_status(server_rec *s, apr_pool_t *p,
~~~

## CVE-2026-29168.patch: affected hunks

~~~text
+++ b/modules/md/md_ocsp.c
@@ -46,7 +46,21 @@
@@ -901,6 +915,12 @@ void md_ocsp_renew(md_ocsp_reg_t *reg, apr_pool_t *p, apr_pool_t *ptemp, apr_tim
~~~

## Decision gates

- Preserve Focal's Apache module ABI; no core API shims in release packages.
- Port bounded retry/backoff math at the matching native Focal call sites.
- Check whether Focal has the affected OCSP HTTP response path before
  considering CVE-2026-29168 not applicable.
- Reuse the existing experimental Focal build and PHP/HTTP test matrix.
