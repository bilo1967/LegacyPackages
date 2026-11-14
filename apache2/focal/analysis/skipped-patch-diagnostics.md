# Remaining Jammy patch candidates: contextual diagnosis

Informational only. No skipped patch is considered fixed. Fuzz=1/2 is diagnostic only and does not authorize patching.

## fix-a-possible-listener-deadlock.patch

Previous result: skipped

Touched paths: server/mpm/event/event.c

### Dry run fuzz=0 exit=1

~~~text
checking file server/mpm/event/event.c
Hunk #1 FAILED at 528.
Hunk #2 FAILED at 774.
Hunk #3 FAILED at 2002.
Hunk #4 succeeded at 2008 (offset -58 lines).
Hunk #5 succeeded at 2023 (offset -58 lines).
Hunk #6 FAILED at 3051.
4 out of 6 hunks FAILED

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file server/mpm/event/event.c
Hunk #1 FAILED at 528.
Hunk #2 FAILED at 774.
Hunk #3 FAILED at 2002.
Hunk #4 succeeded at 2008 (offset -58 lines).
Hunk #5 succeeded at 2023 (offset -58 lines).
Hunk #6 FAILED at 3051.
4 out of 6 hunks FAILED

~~~

### Dry run fuzz=2 exit=1

~~~text
checking file server/mpm/event/event.c
Hunk #1 FAILED at 528.
Hunk #2 FAILED at 774.
Hunk #3 FAILED at 2002.
Hunk #4 succeeded at 2008 (offset -58 lines).
Hunk #5 succeeded at 2023 (offset -58 lines).
Hunk #6 FAILED at 3051.
4 out of 6 hunks FAILED

~~~

### server/mpm/event/event.c

~~~diff
--- a/server/mpm/event/event.c
+++ b/server/mpm/event/event.c
@@ -528,6 +528,11 @@
     return 1;
 }
 
+static APR_INLINE int should_enable_listensocks(void)
+{
+    return !dying && listeners_disabled() && !connections_above_limit(NULL);
+}
+
 static void close_socket_nonblocking_(apr_socket_t *csd,
                                       const char *from, int line)
 {
@@ -774,7 +779,7 @@
     is_last_connection = !apr_atomic_dec32(&connection_count);
     if (listener_is_wakeable
             && ((is_last_connection && listener_may_exit)
-                || (listeners_disabled() && !connections_above_limit(NULL)))) {
+                || should_enable_listensocks())) {
         apr_pollset_wakeup(event_pollset);
     }
     if (dying) {
@@ -2002,9 +2007,7 @@
             }
         }
 
-        if (listeners_disabled()
-                && !workers_were_busy
-                && !connections_above_limit(NULL)) {
+        if (!workers_were_busy && should_enable_listensocks()) {
             enable_listensocks();
         }
     } /* listener main loop */
@@ -2066,7 +2069,7 @@
     ap_update_child_status_from_indexes(process_slot, thread_slot,
                                         SERVER_STARTING, NULL);
 
-    while (!workers_may_exit) {
+    for (;;) {
         apr_socket_t *csd = NULL;
         event_conn_state_t *cs;
         timer_event_t *te = NULL;
@@ -2081,6 +2084,12 @@
                 signal_threads(ST_GRACEFUL);
                 break;
             }
+            /* A new idler may have changed connections_above_limit(),
+             * let the listener know and decide.
+             */
+            if (listener_is_wakeable && should_enable_listensocks()) {
+                apr_pollset_wakeup(event_pollset);
+            }
             is_idle = 1;
         }
 
@@ -3045,7 +3054,7 @@
 
                 event_note_child_killed(child_slot, 0, 0);
                 ps = &ap_scoreboard_image->parent[child_slot];
-                if (!ps->quiescing)
+                if (ps->quiescing != 2)
                     retained->active_daemons--;
                 ps->quiescing = 0;
                 /* NOTE: We don't dec in the (child_slot < 0) case! */

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 520..551
520         }
521     }
522     return 1;
523 }
524 
525 static void abort_socket_nonblocking(apr_socket_t *csd)
526 {
527     apr_status_t rv;
528     apr_socket_timeout_set(csd, 0);
529 #if defined(SOL_SOCKET) && defined(SO_LINGER)
530     /* This socket is over now, and we don't want to block nor linger
531      * anymore, so reset it. A normal close could still linger in the
532      * system, while RST is fast, nonblocking, and what the peer will
533      * get if it sends us further data anyway.
534      */
535     {
536         apr_os_sock_t osd = -1;
537         struct linger opt;
538         opt.l_onoff = 1;
539         opt.l_linger = 0; /* zero timeout is RST */
540         apr_os_sock_get(&osd, csd);
541         setsockopt(osd, SOL_SOCKET, SO_LINGER, (void *)&opt, sizeof opt);
542     }
543 #endif
544     rv = apr_socket_close(csd);
545     if (rv != APR_SUCCESS) {
546         ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(00468)
547                      "error closing socket");
548         AP_DEBUG_ASSERT(0);
549     }
550 }
551 

Focal lines 766..797
766     }
767     /* Unblock the listener if it's waiting for connection_count = 0,
768      * or if the listening sockets were disabled due to limits and can
769      * now accept new connections.
770      */
771     is_last_connection = !apr_atomic_dec32(&connection_count);
772     if (listener_is_wakeable
773             && ((is_last_connection && listener_may_exit)
774                 || (listeners_disabled() && !connections_above_limit()))) {
775         apr_pollset_wakeup(event_pollset);
776     }
777     return APR_SUCCESS;
778 }
779 
780 static void notify_suspend(event_conn_state_t *cs)
781 {
782     ap_run_suspend_connection(cs->c, cs->r);
783     cs->c->sbh = NULL;
784     cs->suspended = 1;
785 }
786 
787 static void notify_resume(event_conn_state_t *cs, int cleanup)
788 {
789     cs->suspended = 0;
790     cs->c->sbh = cleanup ? NULL : cs->sbh;
791     ap_run_resume_connection(cs->c, cs->r);
792 }
793 
794 /*
795  * Close our side of the connection, flushing data to the client first.
796  * Pre-condition: cs is not in any timeout queue and not in the pollset,
797  *                timeout_mutex is not locked

Focal lines 1994..2025
1994  */
1995 static void *APR_THREAD_FUNC worker_thread(apr_thread_t * thd, void *dummy)
1996 {
1997     proc_info *ti = dummy;
1998     int process_slot = ti->pslot;
1999     int thread_slot = ti->tslot;
2000     apr_status_t rv;
2001     int is_idle = 0;
2002 
2003     free(ti);
2004 
2005     ap_scoreboard_image->servers[process_slot][thread_slot].pid = ap_my_pid;
2006     ap_scoreboard_image->servers[process_slot][thread_slot].tid = apr_os_thread_current();
2007     ap_scoreboard_image->servers[process_slot][thread_slot].generation = retained->mpm->my_generation;
2008     ap_update_child_status_from_indexes(process_slot, thread_slot,
2009                                         SERVER_STARTING, NULL);
2010 
2011     while (!workers_may_exit) {
2012         apr_socket_t *csd = NULL;
2013         event_conn_state_t *cs;
2014         timer_event_t *te = NULL;
2015         apr_pool_t *ptrans;         /* Pool for per-transaction stuff */
2016 
2017         if (!is_idle) {
2018             rv = ap_queue_info_set_idle(worker_queue_info, NULL);
2019             if (rv != APR_SUCCESS) {
2020                 ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
2021                              "ap_queue_info_set_idle failed. Attempting to "
2022                              "shutdown process gracefully.");
2023                 signal_threads(ST_GRACEFUL);
2024                 break;
2025             }
~~~

## handle-children-killed-pathologically.patch

Previous result: skipped

Touched paths: server/mpm/event/event.c, server/mpm/worker/worker.c

### Dry run fuzz=0 exit=1

~~~text
checking file server/mpm/event/event.c
Hunk #1 FAILED at 3001.
Hunk #2 succeeded at 2994 (offset -96 lines).
1 out of 2 hunks FAILED
checking file server/mpm/worker/worker.c
Hunk #1 FAILED at 1575.
Hunk #2 succeeded at 1657 (offset -12 lines).
1 out of 2 hunks FAILED

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file server/mpm/event/event.c
Hunk #1 FAILED at 3001.
Hunk #2 succeeded at 2994 (offset -96 lines).
1 out of 2 hunks FAILED
checking file server/mpm/worker/worker.c
Hunk #1 FAILED at 1575.
Hunk #2 succeeded at 1657 (offset -12 lines).
1 out of 2 hunks FAILED

~~~

### Dry run fuzz=2 exit=1

~~~text
checking file server/mpm/event/event.c
Hunk #1 FAILED at 3001.
Hunk #2 succeeded at 2994 (offset -96 lines).
1 out of 2 hunks FAILED
checking file server/mpm/worker/worker.c
Hunk #1 FAILED at 1575.
Hunk #2 succeeded at 1657 (offset -12 lines).
1 out of 2 hunks FAILED

~~~

### server/mpm/event/event.c

~~~diff
--- a/server/mpm/event/event.c
+++ b/server/mpm/event/event.c
@@ -3001,6 +3001,7 @@
 static void server_main_loop(int remaining_children_to_start)
 {
     int num_buckets = retained->mpm->num_buckets;
+    int successive_kills = 0;
     int child_slot;
     apr_exit_why_e exitwhy;
     int status, processed_status;
@@ -3090,11 +3091,30 @@
             /* Don't perform idle maintenance when a child dies,
              * only do it when there's a timeout.  Remember only a
              * finite number of children can die, and it's pretty
-             * pathological for a lot to die suddenly.
+             * pathological for a lot to die suddenly.  If a child is
+             * killed by a signal (faulting) we want to restart it ASAP
+             * though, up to 3 successive faults or we stop this until
+             * a timeout happens again (to avoid the flood of fork()ed
+             * processes that keep being killed early).
              */
-            continue;
+            if (child_slot < 0 || !APR_PROC_CHECK_SIGNALED(exitwhy)) {
+                continue;
+            }
+            if (++successive_kills >= 3) {
+                if (successive_kills % 10 == 3) {
+                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
+                                 ap_server_conf, APLOGNO(10392)
+                                 "children are killed successively!");
+                }
+                continue;
+            }
+            ++remaining_children_to_start;
         }
-        else if (remaining_children_to_start) {
+        else {
+            successive_kills = 0;
+        }
+
+        if (remaining_children_to_start) {
             /* we hit a 1 second timeout in which none of the previous
              * generation of children needed to be reaped... so assume
              * they're all done, and pick up the slack if any is left.

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 2993..3024
2993             }
2994             /* Don't perform idle maintenance when a child dies,
2995              * only do it when there's a timeout.  Remember only a
2996              * finite number of children can die, and it's pretty
2997              * pathological for a lot to die suddenly.
2998              */
2999             continue;
3000         }
3001         else if (remaining_children_to_start) {
3002             /* we hit a 1 second timeout in which none of the previous
3003              * generation of children needed to be reaped... so assume
3004              * they're all done, and pick up the slack if any is left.
3005              */
3006             startup_children(remaining_children_to_start);
3007             remaining_children_to_start = 0;
3008             /* In any event we really shouldn't do the code below because
3009              * few of the servers we just started are in the IDLE state
3010              * yet, so we'd mistakenly create an extra server.
3011              */
3012             continue;
3013         }
3014 
3015         for (i = 0; i < num_buckets; i++) {
3016             perform_idle_server_maintenance(i, num_buckets);
3017         }
3018     }
3019 }
3020 
3021 static int event_run(apr_pool_t * _pconf, apr_pool_t * plog, server_rec * s)
3022 {
3023     int num_buckets = retained->mpm->num_buckets;
3024     int remaining_children_to_start;

Focal lines 3082..3113
3082 
3083     ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(00489)
3084                  "%s configured -- resuming normal operations",
3085                  ap_get_server_description());
3086     ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, APLOGNO(00490)
3087                  "Server built: %s", ap_get_server_built());
3088     ap_log_command_line(plog, s);
3089     ap_log_mpm_common(s);
3090 
3091     retained->mpm->mpm_state = AP_MPMQ_RUNNING;
3092 
3093     server_main_loop(remaining_children_to_start, num_buckets);
3094     retained->mpm->mpm_state = AP_MPMQ_STOPPING;
3095 
3096     if (retained->mpm->shutdown_pending && retained->mpm->is_ungraceful) {
3097         /* Time to shut down:
3098          * Kill child processes, tell them to call child_exit, etc...
3099          */
3100         for (i = 0; i < num_buckets; i++) {
3101             ap_mpm_podx_killpg(all_buckets[i].pod, active_daemons_limit,
3102                                AP_MPM_PODX_RESTART);
3103         }
3104         ap_reclaim_child_processes(1, /* Start with SIGTERM */
3105                                    event_note_child_killed);
3106 
3107         if (!child_fatal) {
3108             /* cleanup pid file on normal shutdown */
3109             ap_remove_pid(pconf, ap_pid_fname);
3110             ap_log_error(APLOG_MARK, APLOG_NOTICE, 0,
3111                          ap_server_conf, APLOGNO(00491) "caught SIGTERM, shutting down");
3112         }
3113 
~~~

### server/mpm/worker/worker.c

~~~diff
--- a/server/mpm/worker/worker.c
+++ b/server/mpm/worker/worker.c
@@ -1575,6 +1575,7 @@
 static void server_main_loop(int remaining_children_to_start)
 {
     int num_buckets = retained->mpm->num_buckets;
+    int successive_kills = 0;
     ap_generation_t old_gen;
     int child_slot;
     apr_exit_why_e exitwhy;
@@ -1669,11 +1670,30 @@
             /* Don't perform idle maintenance when a child dies,
              * only do it when there's a timeout.  Remember only a
              * finite number of children can die, and it's pretty
-             * pathological for a lot to die suddenly.
+             * pathological for a lot to die suddenly.  If a child is
+             * killed by a signal (faulting) we want to restart it ASAP
+             * though, up to 3 successive faults or we stop this until
+             * a timeout happens again (to avoid the flood of fork()ed
+             * processes that keep being killed early).
              */
-            continue;
+            if (child_slot < 0 || !APR_PROC_CHECK_SIGNALED(exitwhy)) {
+                continue;
+            }
+            if (++successive_kills >= 3) {
+                if (successive_kills % 10 == 3) {
+                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
+                                 ap_server_conf, APLOGNO(10392)
+                                 "children are killed successively!");
+                }
+                continue;
+            }
+            ++remaining_children_to_start;
         }
-        else if (remaining_children_to_start) {
+        else {
+            successive_kills = 0;
+        }
+
+        if (remaining_children_to_start) {
             /* we hit a 1 second timeout in which none of the previous
              * generation of children needed to be reaped... so assume
              * they're all done, and pick up the slack if any is left.

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 1567..1598
1567     int child_slot;
1568     apr_exit_why_e exitwhy;
1569     int status, processed_status;
1570     apr_proc_t pid;
1571     int i;
1572 
1573     while (!retained->mpm->restart_pending && !retained->mpm->shutdown_pending) {
1574         ap_wait_or_timeout(&exitwhy, &status, &pid, pconf, ap_server_conf);
1575 
1576         if (pid.pid != -1) {
1577             processed_status = ap_process_child_status(&pid, exitwhy, status);
1578             child_slot = ap_find_child_by_pid(&pid);
1579             if (processed_status == APEXIT_CHILDFATAL) {
1580                 /* fix race condition found in PR 39311
1581                  * A child created at the same time as a graceful happens 
1582                  * can find the lock missing and create a fatal error.
1583                  * It is not fatal for the last generation to be in this state.
1584                  */
1585                 if (child_slot < 0
1586                     || ap_get_scoreboard_process(child_slot)->generation
1587                        == retained->mpm->my_generation) {
1588                     retained->mpm->shutdown_pending = 1;
1589                     child_fatal = 1;
1590                     return;
1591                 }
1592                 else {
1593                     ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, APLOGNO(00290)
1594                                  "Ignoring fatal error in child of previous "
1595                                  "generation (pid %ld).",
1596                                  (long)pid.pid);
1597                     retained->sick_child_detected = 1;
1598                 }

Focal lines 1661..1692
1661              */
1662             continue;
1663         }
1664         else if (remaining_children_to_start) {
1665             /* we hit a 1 second timeout in which none of the previous
1666              * generation of children needed to be reaped... so assume
1667              * they're all done, and pick up the slack if any is left.
1668              */
1669             startup_children(remaining_children_to_start);
1670             remaining_children_to_start = 0;
1671             /* In any event we really shouldn't do the code below because
1672              * few of the servers we just started are in the IDLE state
1673              * yet, so we'd mistakenly create an extra server.
1674              */
1675             continue;
1676         }
1677 
1678         for (i = 0; i < num_buckets; i++) {
1679             perform_idle_server_maintenance(i, num_buckets);
1680         }
1681     }
1682 }
1683 
1684 static int worker_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s)
1685 {
1686     int num_buckets = retained->mpm->num_buckets;
1687     int remaining_children_to_start;
1688     int i;
1689 
1690     ap_log_pid(pconf, ap_pid_fname);
1691 
1692     if (!retained->mpm->was_graceful) {
~~~

## mod_proxy_hcheck_jammy_fix_to_detect_support.patch

Previous result: skipped

Touched paths: modules/proxy/mod_proxy_hcheck.c, mod_proxy_hcheck_jammy_fix_to_detect_support.patch

### Dry run fuzz=0 exit=1

~~~text
checking file modules/proxy/mod_proxy_hcheck.c
Hunk #1 FAILED at 1070.
Hunk #2 FAILED at 1126.
2 out of 2 hunks FAILED
checking file mod_proxy_hcheck_jammy_fix_to_detect_support.patch

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file modules/proxy/mod_proxy_hcheck.c
Hunk #1 FAILED at 1070.
Hunk #2 FAILED at 1126.
2 out of 2 hunks FAILED
checking file mod_proxy_hcheck_jammy_fix_to_detect_support.patch

~~~

### Dry run fuzz=2 exit=1

~~~text
checking file modules/proxy/mod_proxy_hcheck.c
Hunk #1 FAILED at 1070.
Hunk #2 FAILED at 1126.
2 out of 2 hunks FAILED
checking file mod_proxy_hcheck_jammy_fix_to_detect_support.patch

~~~

### modules/proxy/mod_proxy_hcheck.c

~~~diff
--- a/modules/proxy/mod_proxy_hcheck.c
+++ b/modules/proxy/mod_proxy_hcheck.c
@@ -1070,6 +1070,18 @@
     hctp = NULL;
     tpsize = HC_THREADPOOL_SIZE;
 #endif
+
+    ajp_handle_cping_cpong = APR_RETRIEVE_OPTIONAL_FN(ajp_handle_cping_cpong);
+    if (ajp_handle_cping_cpong) {
+       proxy_hcmethods_t *method = proxy_hcmethods;
+       for (; method->name; method++) {
+           if (method->method == CPING) {
+               method->implemented = 1;
+               break;
+           }
+       }
+    }
+
     return OK;
 }
 static int hc_post_config(apr_pool_t *p, apr_pool_t *plog,
@@ -1126,17 +1138,6 @@
         s = s->next;
     }
 
-    ajp_handle_cping_cpong = APR_RETRIEVE_OPTIONAL_FN(ajp_handle_cping_cpong);
-    if (ajp_handle_cping_cpong) {
-       proxy_hcmethods_t *method = proxy_hcmethods;
-       for (; method->name; method++) {
-           if (method->method == CPING) {
-               method->implemented = 1;
-               break;
-           }
-       }
-    }
-
     return OK;
 }
 
--- /dev/null
+++ b/mod_proxy_hcheck_jammy_fix_to_detect_support.patch
@@ -0,0 +1 @@
+

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 1062..1093
1062     const apr_array_header_t *hdr;
1063     int i;
1064     sctx_t *ctx = (sctx_t *) ap_get_module_config(r->server->module_config,
1065                                                   &proxy_hcheck_module);
1066     if (!ctx)
1067         return;
1068     if (apr_is_empty_table(ctx->conditions))
1069         return;
1070 
1071     ap_rputs("\n\n<table>"
1072              "<tr><th colspan='2'>Health check cond. expressions:</th></tr>\n"
1073              "<tr><th>Expr name</th><th>Expression</th></tr>\n", r);
1074 
1075     hdr = apr_table_elts(ctx->conditions);
1076     elts = (const apr_table_entry_t *) hdr->elts;
1077     for (i = 0; i < hdr->nelts; ++i) {
1078         hc_condition_t *cond;
1079         if (!elts[i].key) {
1080             continue;
1081         }
1082         cond = (hc_condition_t *)elts[i].val;
1083         ap_rprintf(r, "<tr><td>%s</td><td>%s</td></tr>\n",
1084                    ap_escape_html(r->pool, elts[i].key),
1085                    ap_escape_html(r->pool, cond->expr));
1086     }
1087     ap_rputs("</table><hr/>\n", r);
1088 }
1089 
1090 static void hc_select_exprs(request_rec *r, const char *expr)
1091 {
1092     const apr_table_entry_t *elts;
1093     const apr_array_header_t *hdr;

Focal lines 1118..1149
1118     const apr_array_header_t *hdr;
1119     int i;
1120     sctx_t *ctx = (sctx_t *) ap_get_module_config(r->server->module_config,
1121                                                   &proxy_hcheck_module);
1122     if (!ctx)
1123         return 0;
1124     if (apr_is_empty_table(ctx->conditions))
1125         return 0;
1126 
1127     hdr = apr_table_elts(ctx->conditions);
1128     elts = (const apr_table_entry_t *) hdr->elts;
1129     for (i = 0; i < hdr->nelts; ++i) {
1130         if (!elts[i].key) {
1131             continue;
1132         }
1133         if (!strcmp(elts[i].key, expr))
1134             return 1;
1135     }
1136     return 0;
1137 }
1138 
1139 static const char *hc_get_body(request_rec *r)
1140 {
1141     apr_off_t length;
1142     apr_size_t len;
1143     apr_status_t rv;
1144     char *buf;
1145 
1146     if (!r || !r->kept_body)
1147         return "";
1148 
1149     rv = apr_brigade_length(r->kept_body, 1, &length);

Focal lines 1..32
1 /* Licensed to the Apache Software Foundation (ASF) under one or more
2  * contributor license agreements.  See the NOTICE file distributed with
3  * this work for additional information regarding copyright ownership.
4  * The ASF licenses this file to You under the Apache License, Version 2.0
5  * (the "License"); you may not use this file except in compliance with
6  * the License.  You may obtain a copy of the License at
7  *
8  *     http://www.apache.org/licenses/LICENSE-2.0
9  *
10  * Unless required by applicable law or agreed to in writing, software
11  * distributed under the License is distributed on an "AS IS" BASIS,
12  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
13  * See the License for the specific language governing permissions and
14  * limitations under the License.
15  */
16 #include "mod_proxy.h"
17 #include "mod_watchdog.h"
18 #include "ap_slotmem.h"
19 #include "ap_expr.h"
20 #if APR_HAS_THREADS
21 #include "apr_thread_pool.h"
22 #endif
23 
24 module AP_MODULE_DECLARE_DATA proxy_hcheck_module;
25 
26 #define HCHECK_WATHCHDOG_NAME ("_proxy_hcheck_")
27 #define HC_THREADPOOL_SIZE (16)
28 
29 /* Why? So we can easily set/clear HC_USE_THREADS during dev testing */
30 #if APR_HAS_THREADS
31 #ifndef HC_USE_THREADS
32 #define HC_USE_THREADS 1
~~~

## reenable-workers-in-standard-error-state-jammy-apache2.patch

Previous result: skipped

Touched paths: include/ap_mmn.h, modules/proxy/mod_proxy.h, modules/proxy/mod_proxy_hcheck.c

### Dry run fuzz=0 exit=1

~~~text
checking file include/ap_mmn.h
Hunk #1 FAILED at 587.
Hunk #2 FAILED at 595.
2 out of 2 hunks FAILED
checking file modules/proxy/mod_proxy.h
Hunk #1 succeeded at 345 (offset -9 lines).
checking file modules/proxy/mod_proxy_hcheck.c
Hunk #1 FAILED at 909.
1 out of 1 hunk FAILED

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file include/ap_mmn.h
Hunk #1 FAILED at 587.
Hunk #2 FAILED at 595.
2 out of 2 hunks FAILED
checking file modules/proxy/mod_proxy.h
Hunk #1 succeeded at 345 (offset -9 lines).
checking file modules/proxy/mod_proxy_hcheck.c
Hunk #1 FAILED at 909.
1 out of 1 hunk FAILED

~~~

### Dry run fuzz=2 exit=1

~~~text
checking file include/ap_mmn.h
Hunk #1 FAILED at 587.
Hunk #2 FAILED at 595.
2 out of 2 hunks FAILED
checking file modules/proxy/mod_proxy.h
Hunk #1 succeeded at 345 (offset -9 lines).
checking file modules/proxy/mod_proxy_hcheck.c
Hunk #1 FAILED at 909.
1 out of 1 hunk FAILED

~~~

### include/ap_mmn.h

~~~diff
--- a/include/ap_mmn.h
+++ b/include/ap_mmn.h
@@ -587,7 +587,8 @@
  * 20120211.120 (2.4.51-dev) Add dav_liveprop_elem structure and
  *                           dav_get_liveprop_element().
  * 20120211.121 (2.4.51-dev) Add ap_post_read_request()
- * 
+ * 20120211.126 (2.4.55-dev) Add additional hcmethod_t enums and
+                             PROXY_WORKER_IS_ERROR
  */
 
 #define MODULE_MAGIC_COOKIE 0x41503234UL /* "AP24" */
@@ -595,7 +596,7 @@
 #ifndef MODULE_MAGIC_NUMBER_MAJOR
 #define MODULE_MAGIC_NUMBER_MAJOR 20120211
 #endif
-#define MODULE_MAGIC_NUMBER_MINOR 121                 /* 0...n */
+#define MODULE_MAGIC_NUMBER_MINOR 126                 /* 0...n */
 
 /**
  * Determine if the server's current MODULE_MAGIC_NUMBER is at least a

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 572..571


Focal lines 572..571

~~~

### modules/proxy/mod_proxy.h

~~~diff
--- a/modules/proxy/mod_proxy.h
+++ b/modules/proxy/mod_proxy.h
@@ -354,6 +354,8 @@
 
 #define PROXY_WORKER_IS_HCFAILED(f)   ( (f)->s->status &  PROXY_WORKER_HC_FAIL )
 
+#define PROXY_WORKER_IS_ERROR(f)   ( (f)->s->status &  PROXY_WORKER_IN_ERROR )
+
 #define PROXY_WORKER_IS(f, b)   ( (f)->s->status & (b) )
 
 /* default worker retry timeout in seconds */

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 346..377
346 #define PROXY_WORKER_IS_HCFAILED(f)   ( (f)->s->status &  PROXY_WORKER_HC_FAIL )
347 
348 #define PROXY_WORKER_IS(f, b)   ( (f)->s->status & (b) )
349 
350 /* default worker retry timeout in seconds */
351 #define PROXY_WORKER_DEFAULT_RETRY    60
352 
353 /* Some max char string sizes, for shm fields */
354 #define PROXY_WORKER_MAX_SCHEME_SIZE    16
355 #define PROXY_WORKER_MAX_ROUTE_SIZE     64
356 #define PROXY_BALANCER_MAX_ROUTE_SIZE PROXY_WORKER_MAX_ROUTE_SIZE
357 #define PROXY_WORKER_MAX_NAME_SIZE      96
358 #define PROXY_BALANCER_MAX_NAME_SIZE PROXY_WORKER_MAX_NAME_SIZE
359 #define PROXY_WORKER_MAX_HOSTNAME_SIZE  64
360 #define PROXY_BALANCER_MAX_HOSTNAME_SIZE PROXY_WORKER_MAX_HOSTNAME_SIZE
361 #define PROXY_BALANCER_MAX_STICKY_SIZE  64
362 #define PROXY_WORKER_MAX_SECRET_SIZE     64
363 
364 #define PROXY_RFC1035_HOSTNAME_SIZE	256
365 
366 /* RFC-1035 mentions limits of 255 for host-names and 253 for domain-names,
367  * dotted together(?) this would fit the below size (+ trailing NUL).
368  */
369 #define PROXY_WORKER_RFC1035_NAME_SIZE  512
370 
371 #define PROXY_MAX_PROVIDER_NAME_SIZE    16
372 
373 #define PROXY_STRNCPY(dst, src) ap_proxy_strncpy((dst), (src), (sizeof(dst)))
374 
375 #define PROXY_COPY_CONF_PARAMS(w, c) \
376 do {                             \
377 (w)->s->timeout              = (c)->timeout;               \
~~~

### modules/proxy/mod_proxy_hcheck.c

~~~diff
--- a/modules/proxy/mod_proxy_hcheck.c
+++ b/modules/proxy/mod_proxy_hcheck.c
@@ -909,7 +909,7 @@
                          (int)hc->s->method);
     }
     /* what state are we in ? */
-    else if (PROXY_WORKER_IS_HCFAILED(worker)) {
+    else if (PROXY_WORKER_IS_HCFAILED(worker) || PROXY_WORKER_IS_ERROR(worker)) {
         if (rv == APR_SUCCESS) {
             worker->s->pcount += 1;
             if (worker->s->pcount >= worker->s->passes) {

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 901..932
901             if (tpsize && hctp == NULL) {
902                 rv =  apr_thread_pool_create(&hctp, tpsize,
903                                              tpsize, ctx->p);
904                 if (rv != APR_SUCCESS) {
905                     ap_log_error(APLOG_MARK, APLOG_INFO, rv, s, APLOGNO(03312)
906                                  "apr_thread_pool_create() with %d threads failed",
907                                  tpsize);
908                     /* we can continue on without the threadpools */
909                     hctp = NULL;
910                 } else {
911                     ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(03313)
912                                  "apr_thread_pool_create() with %d threads succeeded",
913                                  tpsize);
914                 }
915             } else {
916                 ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(03314)
917                              "Skipping apr_thread_pool_create()");
918                 hctp = NULL;
919             }
920 
921 #endif
922             break;
923 
924         case AP_WATCHDOG_STATE_RUNNING:
925             /* loop thru all workers */
926             if (s) {
927                 int i;
928                 conf = (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
929                 balancer = (proxy_balancer *)conf->balancers->elts;
930                 ctx->s = s;
931                 for (i = 0; i < conf->balancers->nelts; i++, balancer++) {
932                     int n;
~~~

## CVE-2024-42516.patch

Previous result: skipped

Touched paths: modules/http/http_filters.c

### Dry run fuzz=0 exit=1

~~~text
checking file modules/http/http_filters.c
Hunk #1 succeeded at 1302 (offset 2 lines).
Hunk #2 succeeded at 1335 (offset 2 lines).
Hunk #3 succeeded at 1357 (offset 2 lines).
Hunk #4 FAILED at 1415.
1 out of 4 hunks FAILED

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file modules/http/http_filters.c
Hunk #1 succeeded at 1302 (offset 2 lines).
Hunk #2 succeeded at 1335 (offset 2 lines).
Hunk #3 succeeded at 1357 (offset 2 lines).
Hunk #4 FAILED at 1415.
1 out of 4 hunks FAILED

~~~

### Dry run fuzz=2 exit=1

~~~text
checking file modules/http/http_filters.c
Hunk #1 succeeded at 1302 (offset 2 lines).
Hunk #2 succeeded at 1335 (offset 2 lines).
Hunk #3 succeeded at 1357 (offset 2 lines).
Hunk #4 FAILED at 1415.
1 out of 4 hunks FAILED

~~~

### modules/http/http_filters.c

~~~diff
--- a/modules/http/http_filters.c
+++ b/modules/http/http_filters.c
@@ -1300,107 +1300,10 @@ typedef struct header_filter_ctx {
     int headers_sent;
 } header_filter_ctx;
 
-AP_CORE_DECLARE_NONSTD(apr_status_t) ap_http_header_filter(ap_filter_t *f,
-                                                           apr_bucket_brigade *b)
+static void merge_response_headers(request_rec *r, const char **protocol)
 {
-    request_rec *r = f->r;
-    conn_rec *c = r->connection;
-    const char *clheader;
-    int header_only = (r->header_only || AP_STATUS_IS_HEADER_ONLY(r->status));
-    const char *protocol = NULL;
-    apr_bucket *e;
-    apr_bucket_brigade *b2;
-    header_struct h;
-    header_filter_ctx *ctx = f->ctx;
-    const char *ctype;
-    ap_bucket_error *eb = NULL;
-    apr_status_t rv = APR_SUCCESS;
-    int recursive_error = 0;
-
-    AP_DEBUG_ASSERT(!r->main);
-
-    if (!ctx) {
-        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(header_filter_ctx));
-    }
-    else if (ctx->headers_sent) {
-        /* Eat body if response must not have one. */
-        if (header_only) {
-            /* Still next filters may be waiting for EOS, so pass it (alone)
-             * when encountered and be done with this filter.
-             */
-            e = APR_BRIGADE_LAST(b);
-            if (e != APR_BRIGADE_SENTINEL(b) && APR_BUCKET_IS_EOS(e)) {
-                APR_BUCKET_REMOVE(e);
-                apr_brigade_cleanup(b);
-                APR_BRIGADE_INSERT_HEAD(b, e);
-                ap_remove_output_filter(f);
-                rv = ap_pass_brigade(f->next, b);
-            }
-            apr_brigade_cleanup(b);
-            return rv;
-        }
-    }
-
-    for (e = APR_BRIGADE_FIRST(b);
-         e != APR_BRIGADE_SENTINEL(b);
-         e = APR_BUCKET_NEXT(e))
-    {
-        if (AP_BUCKET_IS_ERROR(e) && !eb) {
-            eb = e->data;
-            continue;
-        }
-        /*
-         * If we see an EOC bucket it is a signal that we should get out
-         * of the way doing nothing.
-         */
-        if (AP_BUCKET_IS_EOC(e)) {
-            ap_remove_output_filter(f);
-            return ap_pass_brigade(f->next, b);
-        }
-    }
-
-    if (!ctx->headers_sent && !check_headers(r)) {
-        /* We may come back here from ap_die() below,
-         * so clear anything from this response.
-         */
-        apr_table_clear(r->headers_out);
-        apr_table_clear(r->err_headers_out);
-        r->content_type = r->content_encoding = NULL;
-        r->content_languages = NULL;
-        r->clength = r->chunked = 0;
-        apr_brigade_cleanup(b);
-
-        /* Don't recall ap_die() if we come back here (from its own internal
-         * redirect or error response), otherwise we can end up in infinite
-         * recursion; better fall through with 500, minimal headers and an
-         * empty body (EOS only).
-         */
-        if (!check_headers_recursion(r)) {
-            ap_die(HTTP_INTERNAL_SERVER_ERROR, r);
-            return AP_FILTER_ERROR;
-        }
-        r->status = HTTP_INTERNAL_SERVER_ERROR;
-        e = ap_bucket_eoc_create(c->bucket_alloc);
-        APR_BRIGADE_INSERT_TAIL(b, e);
-        e = apr_bucket_eos_create(c->bucket_alloc);
-        APR_BRIGADE_INSERT_TAIL(b, e);
-        ap_set_content_length(r, 0);
-        recursive_error = 1;
-    }
-    else if (eb) {
-        int status;
-        status = eb->status;
-        apr_brigade_cleanup(b);
-        ap_die(status, r);
-        return AP_FILTER_ERROR;
-    }
-
-    if (r->assbackwards) {
-        r->sent_bodyct = 1;
-        ap_remove_output_filter(f);
-        rv = ap_pass_brigade(f->next, b);
-        goto out;
-    }
+    const char *ctype = NULL;
+    const char *clheader = NULL;
 
     /*
      * Now that we are ready to send a response, we need to combine the two
@@ -1430,6 +1333,9 @@ AP_CORE_DECLARE_NONSTD(apr_status_t) ap_http_header_filter(ap_filter_t *f,
         fixup_vary(r);
     }
 
+    /* determine the protocol and whether we should use keepalives. */
+    basic_http_header_check(r, protocol);
+    ap_set_keepalive(r);
 
     /*
      * Control cachability for non-cacheable responses if not already set by
@@ -1449,10 +1355,6 @@ AP_CORE_DECLARE_NONSTD(apr_status_t) ap_http_header_filter(ap_filter_t *f,
         apr_table_unset(r->headers_out, "ETag");
     }
 
-    /* determine the protocol and whether we should use keepalives. */
-    basic_http_header_check(r, &protocol);
-    ap_set_keepalive(r);
-
  
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 1292..1323
1292                                    r->pool, bb->bucket_alloc);
1293         APR_BRIGADE_INSERT_TAIL(bb, b);
1294     }
1295 
1296     ap_pass_brigade(r->output_filters,  bb);
1297 
1298     return DONE;
1299 }
1300 
1301 typedef struct header_filter_ctx {
1302     int headers_sent;
1303 } header_filter_ctx;
1304 
1305 AP_CORE_DECLARE_NONSTD(apr_status_t) ap_http_header_filter(ap_filter_t *f,
1306                                                            apr_bucket_brigade *b)
1307 {
1308     request_rec *r = f->r;
1309     conn_rec *c = r->connection;
1310     const char *clheader;
1311     int header_only = (r->header_only || AP_STATUS_IS_HEADER_ONLY(r->status));
1312     const char *protocol = NULL;
1313     apr_bucket *e;
1314     apr_bucket_brigade *b2;
1315     header_struct h;
1316     header_filter_ctx *ctx = f->ctx;
1317     const char *ctype;
1318     ap_bucket_error *eb = NULL;
1319     apr_status_t rv = APR_SUCCESS;
1320     int recursive_error = 0;
1321 
1322     AP_DEBUG_ASSERT(!r->main);
1323 

Focal lines 1422..1453
1422      *
1423      * Note: the force-response-1.0 should come before the call to
1424      *       basic_http_header_check()
1425      */
1426     if (apr_table_get(r->subprocess_env, "force-no-vary") != NULL) {
1427         apr_table_unset(r->headers_out, "Vary");
1428         r->proto_num = HTTP_VERSION(1,0);
1429         apr_table_setn(r->subprocess_env, "force-response-1.0", "1");
1430     }
1431     else {
1432         fixup_vary(r);
1433     }
1434 
1435 
1436     /*
1437      * Control cachability for non-cacheable responses if not already set by
1438      * some other part of the server configuration.
1439      */
1440     if (r->no_cache && !apr_table_get(r->headers_out, "Expires")) {
1441         char *date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
1442         ap_recent_rfc822_date(date, r->request_time);
1443         apr_table_addn(r->headers_out, "Expires", date);
1444     }
1445 
1446     /*
1447      * Now remove any ETag response header field if earlier processing
1448      * says so (such as a 'FileETag None' directive).
1449      */
1450     if (apr_table_get(r->notes, "no-etag") != NULL) {
1451         apr_table_unset(r->headers_out, "ETag");
1452     }
1453 

Focal lines 1441..1472
1441         char *date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
1442         ap_recent_rfc822_date(date, r->request_time);
1443         apr_table_addn(r->headers_out, "Expires", date);
1444     }
1445 
1446     /*
1447      * Now remove any ETag response header field if earlier processing
1448      * says so (such as a 'FileETag None' directive).
1449      */
1450     if (apr_table_get(r->notes, "no-etag") != NULL) {
1451         apr_table_unset(r->headers_out, "ETag");
1452     }
1453 
1454     /* determine the protocol and whether we should use keepalives. */
1455     basic_http_header_check(r, &protocol);
1456     ap_set_keepalive(r);
1457 
1458     /* 204/304 responses don't have content related headers */
1459     if (AP_STATUS_IS_HEADER_ONLY(r->status)) {
1460         apr_table_unset(r->headers_out, "Transfer-Encoding");
1461         apr_table_unset(r->headers_out, "Content-Length");
1462         r->content_type = r->content_encoding = NULL;
1463         r->content_languages = NULL;
1464         r->clength = r->chunked = 0;
1465     }
1466     else if (r->chunked) {
1467         apr_table_mergen(r->headers_out, "Transfer-Encoding", "chunked");
1468         apr_table_unset(r->headers_out, "Content-Length");
1469     }
1470 
1471     ctype = ap_make_content_type(r, r->content_type);
1472     if (ctype) {
~~~

## CVE-2024-43204-pre1.patch

Previous result: skipped

Touched paths: modules/metadata/mod_headers.c

### Dry run fuzz=0 exit=1

~~~text
checking file modules/metadata/mod_headers.c
Hunk #1 FAILED at 782.
Hunk #2 succeeded at 810 (offset 13 lines).
Hunk #3 succeeded at 826 (offset 13 lines).
1 out of 3 hunks FAILED

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file modules/metadata/mod_headers.c
Hunk #1 FAILED at 782.
Hunk #2 succeeded at 810 (offset 13 lines).
Hunk #3 succeeded at 826 (offset 13 lines).
1 out of 3 hunks FAILED

~~~

### Dry run fuzz=2 exit=1

~~~text
checking file modules/metadata/mod_headers.c
Hunk #1 FAILED at 782.
Hunk #2 succeeded at 810 (offset 13 lines).
Hunk #3 succeeded at 826 (offset 13 lines).
1 out of 3 hunks FAILED

~~~

### modules/metadata/mod_headers.c

~~~diff
--- a/modules/metadata/mod_headers.c
+++ b/modules/metadata/mod_headers.c
@@ -782,14 +782,16 @@ static int do_headers_fixup(request_rec *r, apr_table_t *headers,
             }
             break;
         case hdr_set:
-            if (!ap_cstr_casecmp(hdr->header, "Content-Type")) {
+            if (r->headers_in != headers &&
+                !ap_cstr_casecmp(hdr->header, "Content-Type")) {
                  ap_set_content_type_ex(r, process_tags(hdr, r), 1);
             }
             apr_table_setn(headers, hdr->header, process_tags(hdr, r));
             break;
         case hdr_setifempty:
             if (NULL == apr_table_get(headers, hdr->header)) {
-                if (!ap_cstr_casecmp(hdr->header, "Content-Type")) {
+                if (r->headers_in != headers &&
+                    !ap_cstr_casecmp(hdr->header, "Content-Type")) {
                     ap_set_content_type_ex(r, process_tags(hdr, r), 1);
                 }
                 apr_table_setn(headers, hdr->header, process_tags(hdr, r));
@@ -797,6 +799,10 @@ static int do_headers_fixup(request_rec *r, apr_table_t *headers,
             break;
         case hdr_unset:
             apr_table_unset(headers, hdr->header);
+            if (r->headers_in != headers &&
+                !ap_cstr_casecmp(hdr->header, "Content-Type")) {
+                ap_set_content_type(r, NULL);
+            }
             break;
         case hdr_echo:
             v.r = r;
@@ -809,7 +815,7 @@ static int do_headers_fixup(request_rec *r, apr_table_t *headers,
                 const char *repl = process_regexp(hdr, r->content_type, r);
                 if (repl == NULL)
                     return 0;
-                ap_set_content_type_ex(r, repl, 1);
+                if (r->headers_in != headers) ap_set_content_type_ex(r, repl, 1);
             }
             if (apr_table_get(headers, hdr->header)) {
                 edit_do ed;

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 774..805
774 
775                     while (*val && *val != ',') {
776                         if (*val++ == '"')
777                             while (*val)
778                                 if (*val++ == '"')
779                                     break;
780                     }
781 
782                     if (new_val_len == (apr_size_t)(val - tok_start)
783                         && !strncmp(tok_start, new_val, new_val_len)) {
784                         tok_found = 1;
785                         break;
786                     }
787 
788                     if (*val)
789                         ++val;
790                 }
791 
792                 if (!tok_found) {
793                     apr_table_mergen(headers, hdr->header, new_val);
794                 }
795             }
796             break;
797         case hdr_set:
798             if (!strcasecmp(hdr->header, "Content-Type")) {
799                  ap_set_content_type_ex(r, process_tags(hdr, r), 1);
800             }
801             apr_table_setn(headers, hdr->header, process_tags(hdr, r));
802             break;
803         case hdr_setifempty:
804             if (NULL == apr_table_get(headers, hdr->header)) {
805                 if (!strcasecmp(hdr->header, "Content-Type")) {

Focal lines 789..820
789                         ++val;
790                 }
791 
792                 if (!tok_found) {
793                     apr_table_mergen(headers, hdr->header, new_val);
794                 }
795             }
796             break;
797         case hdr_set:
798             if (!strcasecmp(hdr->header, "Content-Type")) {
799                  ap_set_content_type_ex(r, process_tags(hdr, r), 1);
800             }
801             apr_table_setn(headers, hdr->header, process_tags(hdr, r));
802             break;
803         case hdr_setifempty:
804             if (NULL == apr_table_get(headers, hdr->header)) {
805                 if (!strcasecmp(hdr->header, "Content-Type")) {
806                     ap_set_content_type_ex(r, process_tags(hdr, r), 1);
807                 }
808                 apr_table_setn(headers, hdr->header, process_tags(hdr, r));
809             }
810             break;
811         case hdr_unset:
812             apr_table_unset(headers, hdr->header);
813             break;
814         case hdr_echo:
815             v.r = r;
816             v.hdr = hdr;
817             apr_table_do(echo_header, &v, r->headers_in, NULL);
818             break;
819         case hdr_edit:
820         case hdr_edit_r:

Focal lines 801..832
801             apr_table_setn(headers, hdr->header, process_tags(hdr, r));
802             break;
803         case hdr_setifempty:
804             if (NULL == apr_table_get(headers, hdr->header)) {
805                 if (!strcasecmp(hdr->header, "Content-Type")) {
806                     ap_set_content_type_ex(r, process_tags(hdr, r), 1);
807                 }
808                 apr_table_setn(headers, hdr->header, process_tags(hdr, r));
809             }
810             break;
811         case hdr_unset:
812             apr_table_unset(headers, hdr->header);
813             break;
814         case hdr_echo:
815             v.r = r;
816             v.hdr = hdr;
817             apr_table_do(echo_header, &v, r->headers_in, NULL);
818             break;
819         case hdr_edit:
820         case hdr_edit_r:
821             if (!strcasecmp(hdr->header, "Content-Type") && r->content_type) {
822                 const char *repl = process_regexp(hdr, r->content_type, r);
823                 if (repl == NULL)
824                     return 0;
825                 ap_set_content_type_ex(r, repl, 1);
826             }
827             if (apr_table_get(headers, hdr->header)) {
828                 edit_do ed;
829 
830                 ed.r = r;
831                 ed.hdr = hdr;
832                 ed.t = apr_table_make(r->pool, 5);
~~~

## CVE-2024-43204.patch

Previous result: skipped

Touched paths: modules/metadata/mod_headers.c

### Dry run fuzz=0 exit=1

~~~text
checking file modules/metadata/mod_headers.c
Hunk #1 FAILED at 784.
Hunk #2 FAILED at 792.
2 out of 2 hunks FAILED

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file modules/metadata/mod_headers.c
Hunk #1 FAILED at 784.
Hunk #2 FAILED at 792.
2 out of 2 hunks FAILED

~~~

### Dry run fuzz=2 exit=1

~~~text
checking file modules/metadata/mod_headers.c
Hunk #1 FAILED at 784.
Hunk #2 FAILED at 792.
2 out of 2 hunks FAILED

~~~

### modules/metadata/mod_headers.c

~~~diff
--- a/modules/metadata/mod_headers.c
+++ b/modules/metadata/mod_headers.c
@@ -784,7 +784,7 @@ static int do_headers_fixup(request_rec *r, apr_table_t *headers,
         case hdr_set:
             if (r->headers_in != headers &&
                 !ap_cstr_casecmp(hdr->header, "Content-Type")) {
-                 ap_set_content_type_ex(r, process_tags(hdr, r), 1);
+                 ap_set_content_type(r, process_tags(hdr, r));
             }
             apr_table_setn(headers, hdr->header, process_tags(hdr, r));
             break;
@@ -792,7 +792,7 @@ static int do_headers_fixup(request_rec *r, apr_table_t *headers,
             if (NULL == apr_table_get(headers, hdr->header)) {
                 if (r->headers_in != headers &&
                     !ap_cstr_casecmp(hdr->header, "Content-Type")) {
-                    ap_set_content_type_ex(r, process_tags(hdr, r), 1);
+                    ap_set_content_type(r, process_tags(hdr, r));
                 }
                 apr_table_setn(headers, hdr->header, process_tags(hdr, r));
             }

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 776..807
776                         if (*val++ == '"')
777                             while (*val)
778                                 if (*val++ == '"')
779                                     break;
780                     }
781 
782                     if (new_val_len == (apr_size_t)(val - tok_start)
783                         && !strncmp(tok_start, new_val, new_val_len)) {
784                         tok_found = 1;
785                         break;
786                     }
787 
788                     if (*val)
789                         ++val;
790                 }
791 
792                 if (!tok_found) {
793                     apr_table_mergen(headers, hdr->header, new_val);
794                 }
795             }
796             break;
797         case hdr_set:
798             if (!strcasecmp(hdr->header, "Content-Type")) {
799                  ap_set_content_type_ex(r, process_tags(hdr, r), 1);
800             }
801             apr_table_setn(headers, hdr->header, process_tags(hdr, r));
802             break;
803         case hdr_setifempty:
804             if (NULL == apr_table_get(headers, hdr->header)) {
805                 if (!strcasecmp(hdr->header, "Content-Type")) {
806                     ap_set_content_type_ex(r, process_tags(hdr, r), 1);
807                 }

Focal lines 784..815
784                         tok_found = 1;
785                         break;
786                     }
787 
788                     if (*val)
789                         ++val;
790                 }
791 
792                 if (!tok_found) {
793                     apr_table_mergen(headers, hdr->header, new_val);
794                 }
795             }
796             break;
797         case hdr_set:
798             if (!strcasecmp(hdr->header, "Content-Type")) {
799                  ap_set_content_type_ex(r, process_tags(hdr, r), 1);
800             }
801             apr_table_setn(headers, hdr->header, process_tags(hdr, r));
802             break;
803         case hdr_setifempty:
804             if (NULL == apr_table_get(headers, hdr->header)) {
805                 if (!strcasecmp(hdr->header, "Content-Type")) {
806                     ap_set_content_type_ex(r, process_tags(hdr, r), 1);
807                 }
808                 apr_table_setn(headers, hdr->header, process_tags(hdr, r));
809             }
810             break;
811         case hdr_unset:
812             apr_table_unset(headers, hdr->header);
813             break;
814         case hdr_echo:
815             v.r = r;
~~~

## CVE-2025-23048-regression.patch

Previous result: skipped

Touched paths: modules/ssl/mod_ssl.c, modules/ssl/ssl_engine_config.c, modules/ssl/ssl_engine_init.c, modules/ssl/ssl_engine_kernel.c, modules/ssl/ssl_private.h

### Dry run fuzz=0 exit=1

~~~text
checking file modules/ssl/mod_ssl.c
checking file modules/ssl/ssl_engine_config.c
Hunk #2 succeeded at 1895 (offset -7 lines).
checking file modules/ssl/ssl_engine_init.c
Hunk #2 succeeded at 186 (offset -3 lines).
Hunk #3 succeeded at 528 (offset -8 lines).
checking file modules/ssl/ssl_engine_kernel.c
checking file modules/ssl/ssl_private.h
Hunk #1 succeeded at 494 (offset -8 lines).
Hunk #2 FAILED at 641.
Hunk #3 succeeded at 776 (offset -19 lines).
Hunk #4 succeeded at 855 (offset -19 lines).
1 out of 4 hunks FAILED

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file modules/ssl/mod_ssl.c
checking file modules/ssl/ssl_engine_config.c
Hunk #2 succeeded at 1895 (offset -7 lines).
checking file modules/ssl/ssl_engine_init.c
Hunk #2 succeeded at 186 (offset -3 lines).
Hunk #3 succeeded at 528 (offset -8 lines).
checking file modules/ssl/ssl_engine_kernel.c
checking file modules/ssl/ssl_private.h
Hunk #1 succeeded at 494 (offset -8 lines).
Hunk #2 FAILED at 641.
Hunk #3 succeeded at 776 (offset -19 lines).
Hunk #4 succeeded at 855 (offset -19 lines).
1 out of 4 hunks FAILED

~~~

### Dry run fuzz=2 exit=0

~~~text
checking file modules/ssl/mod_ssl.c
checking file modules/ssl/ssl_engine_config.c
Hunk #2 succeeded at 1895 (offset -7 lines).
checking file modules/ssl/ssl_engine_init.c
Hunk #2 succeeded at 186 (offset -3 lines).
Hunk #3 succeeded at 528 (offset -8 lines).
checking file modules/ssl/ssl_engine_kernel.c
checking file modules/ssl/ssl_private.h
Hunk #1 succeeded at 494 (offset -8 lines).
Hunk #2 succeeded at 629 with fuzz 2 (offset -12 lines).
Hunk #3 succeeded at 778 (offset -19 lines).
Hunk #4 succeeded at 857 (offset -19 lines).

~~~

### modules/ssl/mod_ssl.c

~~~diff
--- a/modules/ssl/mod_ssl.c
+++ b/modules/ssl/mod_ssl.c
@@ -83,6 +83,8 @@ static const command_rec ssl_config_cmds
     SSL_CMD_SRV(RandomSeed, TAKE23,
                 "SSL Pseudo Random Number Generator (PRNG) seeding source "
                 "('startup|connect builtin|file:/path|exec:/path [bytes]')")
+    SSL_CMD_SRV(VHostSNIPolicy, TAKE1,
+                "SSL VirtualHost SNI compatibility policy setting")
 
     /*
      * Per-server context configuration directives

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 75..106
75     SSL_CMD_SRV(SessionCache, TAKE1,
76                 "SSL Session Cache storage "
77                 "('none', 'nonenotnull', 'dbm:/path/to/file')")
78 #if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_INIT)
79     SSL_CMD_SRV(CryptoDevice, TAKE1,
80                 "SSL external Crypto Device usage "
81                 "('builtin', '...')")
82 #endif
83     SSL_CMD_SRV(RandomSeed, TAKE23,
84                 "SSL Pseudo Random Number Generator (PRNG) seeding source "
85                 "('startup|connect builtin|file:/path|exec:/path [bytes]')")
86 
87     /*
88      * Per-server context configuration directives
89      */
90     SSL_CMD_SRV(Engine, TAKE1,
91                 "SSL switch for the protocol engine "
92                 "('on', 'off')")
93     SSL_CMD_SRV(FIPS, FLAG,
94                 "Enable FIPS-140 mode "
95                 "(`on', `off')")
96     SSL_CMD_ALL(CipherSuite, TAKE12,
97                 "Colon-delimited list of permitted SSL Ciphers, optional preceded "
98                 "by protocol identifier ('XXX:...:XXX' - see manual)")
99     SSL_CMD_SRV(CertificateFile, TAKE1,
100                 "SSL Server Certificate file "
101                 "('/path/to/file' - PEM or DER encoded)")
102     SSL_CMD_SRV(CertificateKeyFile, TAKE1,
103                 "SSL Server Private Key file "
104                 "('/path/to/file' - PEM or DER encoded)")
105     SSL_CMD_SRV(CertificateChainFile, TAKE1,
106                 "SSL Server CA Certificate Chain file "
~~~

### modules/ssl/ssl_engine_config.c

~~~diff
--- a/modules/ssl/ssl_engine_config.c
+++ b/modules/ssl/ssl_engine_config.c
@@ -62,6 +62,9 @@ SSLModConfigRec *ssl_config_global_creat
     mc->sesscache_mode         = SSL_SESS_CACHE_OFF;
     mc->sesscache              = NULL;
     mc->pMutex                 = NULL;
+#ifdef HAVE_TLSEXT
+    mc->snivh_policy           = MODSSL_SNIVH_SECURE;
+#endif
     mc->aRandSeed              = apr_array_make(pool, 4,
                                                 sizeof(ssl_randseed_t));
     mc->tVHostKeys             = apr_hash_make(pool);
@@ -1899,6 +1902,41 @@ const char  *ssl_cmd_SSLStrictSNIVHostCh
 #endif
 }
 
+const char *ssl_cmd_SSLVHostSNIPolicy(cmd_parms *cmd, void *dcfg, const char *arg)
+{
+#ifdef HAVE_TLSEXT
+    SSLModConfigRec *mc = myModConfig(cmd->server);
+    const char *err;
+
+    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
+        return err;
+    }
+
+    if (strcEQ(arg, "secure")) {
+        mc->snivh_policy = MODSSL_SNIVH_SECURE;
+    }
+    else if (strcEQ(arg, "strict")) {
+        mc->snivh_policy = MODSSL_SNIVH_STRICT;
+    }
+    else if (strcEQ(arg, "insecure")) {
+        mc->snivh_policy = MODSSL_SNIVH_INSECURE;
+    }
+    else if (strcEQ(arg, "authonly")) {
+        mc->snivh_policy = MODSSL_SNIVH_AUTHONLY;
+    }
+    else {
+        return apr_psprintf(cmd->pool, "Invalid SSLVhostSNIPolicy "
+                            "argument '%s'", arg);
+    }
+
+    return NULL;
+#else
+    return "SSLVHostSNIPolicy cannot be used, OpenSSL is not built with "
+        "support for TLS extensions and SNI indication. Refer to the "
+        "documentation, and build a compatible version of OpenSSL."
+#endif
+}
+
 #ifdef HAVE_OCSP_STAPLING
 
 const char *ssl_cmd_SSLStaplingCache(cmd_parms *cmd,

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 54..85
54      */
55     mc = (SSLModConfigRec *)apr_palloc(pool, sizeof(*mc));
56     mc->pPool = pool;
57     mc->bFixed = FALSE;
58 
59     /*
60      * initialize per-module configuration
61      */
62     mc->sesscache_mode         = SSL_SESS_CACHE_OFF;
63     mc->sesscache              = NULL;
64     mc->pMutex                 = NULL;
65     mc->aRandSeed              = apr_array_make(pool, 4,
66                                                 sizeof(ssl_randseed_t));
67     mc->tVHostKeys             = apr_hash_make(pool);
68     mc->tPrivateKey            = apr_hash_make(pool);
69 #if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_INIT)
70     mc->szCryptoDevice         = NULL;
71 #endif
72 #ifdef HAVE_OCSP_STAPLING
73     mc->stapling_cache         = NULL;
74     mc->stapling_cache_mutex   = NULL;
75     mc->stapling_refresh_mutex = NULL;
76 #endif
77 
78     apr_pool_userdata_set(mc, SSL_MOD_CONFIG_KEY,
79                           apr_pool_cleanup_null,
80                           pool);
81 
82     return mc;
83 }
84 
85 void ssl_config_global_fix(SSLModConfigRec *mc)

Focal lines 1891..1922
1891            "documentation, and build a compatible version of OpenSSL.";
1892 #endif
1893 }
1894 
1895 #ifdef HAVE_OCSP_STAPLING
1896 
1897 const char *ssl_cmd_SSLStaplingCache(cmd_parms *cmd,
1898                                     void *dcfg,
1899                                     const char *arg)
1900 {
1901     SSLModConfigRec *mc = myModConfig(cmd->server);
1902     const char *err, *sep, *name;
1903 
1904     if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
1905         return err;
1906     }
1907 
1908     /* Argument is of form 'name:args' or just 'name'. */
1909     sep = ap_strchr_c(arg, ':');
1910     if (sep) {
1911         name = apr_pstrmemdup(cmd->pool, arg, sep - arg);
1912         sep++;
1913     }
1914     else {
1915         name = arg;
1916     }
1917 
1918     /* Find the provider of given name. */
1919     mc->stapling_cache = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP,
1920                                             name,
1921                                             AP_SOCACHE_PROVIDER_VERSION);
1922     if (mc->stapling_cache) {
~~~

### modules/ssl/ssl_engine_init.c

~~~diff
--- a/modules/ssl/ssl_engine_init.c
+++ b/modules/ssl/ssl_engine_init.c
@@ -27,6 +27,8 @@
                                   see Recursive.''
                                         -- Unknown   */
 #include "ssl_private.h"
+#include <apr_md5.h>
+
 #include "mod_ssl.h"
 #include "mod_ssl_openssl.h"
 #include "mpm_common.h"
@@ -187,6 +189,110 @@ static void ssl_add_version_components(a
                  modver, AP_SERVER_BASEVERSION, incver);
 }
 
+#ifdef HAVE_TLSEXT
+/* Helper functions to create the SNI vhost policy hash. The policy
+ * hash captures the configuration elements relevant to the mode
+ * selected at runtime by SSLVHostSNIPolicy. */
+
+#define md5_str_update(ctx_, pfx_, str_) do { apr_md5_update(ctx_, pfx_, strlen(pfx_)); apr_md5_update(ctx_, str_, strlen(str_)); } while (0)
+#define md5_ifstr_update(ctx_, pfx_, str_) do { apr_md5_update(ctx_, pfx_, strlen(pfx_)); if (str_) apr_md5_update(ctx_, str_, strlen(str_)); } while (0)
+#define md5_fmt_update(ctx_, fmt_, i_) do { char s_[128]; apr_snprintf(s_, sizeof s_, fmt_, i_); \
+        apr_md5_update(ctx_, s_, strlen(s_)); } while (0)
+
+static int md5_strarray_cmp(const void *p1, const void *p2)
+{
+    return strcmp(*(char **)p1, *(char **)p2);
+}
+
+/* Hashes an array of strings in sorted order. */
+static void md5_strarray_hash(apr_pool_t *ptemp, apr_md5_ctx_t *hash,
+                              const char *pfx, apr_array_header_t *s)
+{
+    char **elts = apr_pmemdup(ptemp, s->elts, s->nelts * sizeof *elts);
+    int i;
+
+    qsort(elts, s->nelts, sizeof(char *), md5_strarray_cmp);
+
+    apr_md5_update(hash, pfx, strlen(pfx));
+    for (i = 0; i < s->nelts; i++) {
+        md5_str_update(hash, "elm:", elts[i]);
+    }
+}
+
+static void hash_sni_policy_pk(apr_pool_t *ptemp, apr_md5_ctx_t *hash, modssl_ctx_t *ctx)
+{
+    md5_fmt_update(hash, "protocol:%d", ctx->protocol);
+
+    md5_ifstr_update(hash, "ciphers:", ctx->auth.cipher_suite);
+    md5_ifstr_update(hash, "tls13_ciphers:", ctx->auth.tls13_ciphers);
+
+    md5_strarray_hash(ptemp, hash, "cert_files:", ctx->pks->cert_files);
+    md5_strarray_hash(ptemp, hash, "key_files:", ctx->pks->key_files);
+}
+
+static void hash_sni_policy_auth(apr_md5_ctx_t *hash, modssl_ctx_t *ctx)
+{
+    modssl_pk_server_t *pks = ctx->pks;
+    modssl_auth_ctx_t *a = &ctx->auth;
+
+    md5_fmt_update(hash, "verify_depth:%d", a->verify_depth);
+    md5_fmt_update(hash, "verify_mode:%d", a->verify_mode);
+
+    md5_ifstr_update(hash, "ca_name_path:", pks->ca_name_path);
+    md5_ifstr_update(hash, "ca_name_file:", pks->ca_name_file);
+    md5_ifstr_update(hash, "ca_cert_path:", a->ca_cert_path);
+    md5_ifstr_update(hash, "ca_cert_file:", a->ca_cert_file);
+    md5_ifstr_update(hash, "crl_path:", ctx->crl_path);
+    md5_ifstr_update(hash, "crl_file:", ctx->crl_file);
+    md5_fmt_update(hash, "crl_check_mask:%d", ctx->crl_check_mask);
+    md5_fmt_update(hash, "ocsp_mask:%d", ctx->ocsp_mask);
+    md5_fmt_update(hash, "ocsp_force_default:%d", ctx->ocsp_force_default);
+    md5_ifstr_update(hash, "ocsp_responder:", ctx->ocsp_responder);
+
+#ifdef HAVE_SRP
+    md5_ifstr_update(hash, "srp_vfile:", ctx->srp_vfile);
+#endif
+
+#ifdef HAVE_SSL_CONF_CMD
+    {
+        apr_array_header_t *parms = ctx->ssl_ctx_param;
+        int n;
+
+        for (n = 0; n < parms->nelts; n++) {
+            ssl_ctx_param_t *p = &APR_ARRAY_IDX(parms, n, ssl_ctx_param_t);
+
+            md5_str_update(hash, "param:", p->name);
+            md5_str_update(hash, "value:", p->value);
+        }
+    }
+#endif
+}
+#endif
+
+static char *create_sni_policy_hash(apr_pool_t *p, apr_pool_t *ptemp,
+                                    modssl_snivhpolicy_t policy,
+                                    SSLSrvConfigRec *sc)
+{
+    char *rv = NULL;
+#ifdef HAVE_TLSEXT
+    if (policy != MODSSL_SNIVH_STRICT && policy != MODSSL_SNIVH_INSECURE) {
+        apr_md5_ctx_t hash;
+        unsigned char digest[APR_MD5_DIGESTSIZE];
+
+        /* Create the vhost policy hash for comparison later. */
+        apr_md5_init(&hash);
+        hash_sni_policy_auth(&hash, sc->server);
+        if (policy == MODSSL_SNIVH_SECURE)
+            hash_sni_policy_pk(ptemp, &hash, sc->server);
+        apr_md5_final(digest, &hash);
+
+        rv = apr_palloc(p, 2 * APR_MD5_DIGESTSIZE + 1);
+        ap_bin2hex(digest, APR_MD5_DIGESTSIZE, rv); /* sets final '\0' */
+    }
+#endif
+    return rv;
+}
+
 /*  _________________________________________________________________
 **
 *
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 19..50
19  * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
20  * | | | | | | (_) | (_| |   \__ \__ \ |
21  * |_| |_| |_|\___/ \__,_|___|___/___/_|
22  *                      |_____|
23  *  ssl_engine_init.c
24  *  Initialization of Servers
25  */
26                              /* ``Recursive, adj.;
27                                   see Recursive.''
28                                         -- Unknown   */
29 #include "ssl_private.h"
30 #include "mod_ssl.h"
31 #include "mod_ssl_openssl.h"
32 #include "mpm_common.h"
33 #include "mod_md.h"
34 
35 APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ssl, SSL, int, init_server,
36                                     (server_rec *s,apr_pool_t *p,int is_proxy,SSL_CTX *ctx),
37                                     (s,p,is_proxy,ctx), OK, DECLINED)
38 
39 APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ssl, SSL, int, add_cert_files,
40                                     (server_rec *s, apr_pool_t *p, 
41                                     apr_array_header_t *cert_files, apr_array_header_t *key_files),
42                                     (s, p, cert_files, key_files),
43                                     OK, DECLINED)
44 
45 APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ssl, SSL, int, add_fallback_cert_files,
46                                     (server_rec *s, apr_pool_t *p, 
47                                     apr_array_header_t *cert_files, apr_array_header_t *key_files),
48                                     (s, p, cert_files, key_files),
49                                     OK, DECLINED)
50 

Focal lines 179..210
179 
180     ap_add_version_component(p, libver);
181 
182     ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(01876)
183                  "%s compiled against Server: %s, Library: %s",
184                  modver, AP_SERVER_BASEVERSION, incver);
185 }
186 
187 /*  _________________________________________________________________
188 **
189 **  Let other answer special connection attempts. 
190 **  Used in ACME challenge handling by mod_md.
191 **  _________________________________________________________________
192 */
193 
194 int ssl_is_challenge(conn_rec *c, const char *servername, 
195                      X509 **pcert, EVP_PKEY **pkey)
196 {
197     if (APR_SUCCESS == ssl_run_answer_challenge(c, servername, pcert, pkey)) {
198         return 1;
199     }
200     *pcert = NULL;
201     *pkey = NULL;
202     return 0;
203 }
204 
205 #ifdef HAVE_FIPS
206 static apr_status_t modssl_fips_cleanup(void *data)
207 {
208     FIPS_mode_set(0);
209     return APR_SUCCESS;
210 }

Focal lines 422..453
422                 return rv;
423             }
424         }
425     }
426 
427     /*
428      *  Announce mod_ssl and SSL library in HTTP Server field
429      *  as ``mod_ssl/X.X.X OpenSSL/X.X.X''
430      */
431     ssl_add_version_components(p, base_server);
432 
433     modssl_init_app_data2_idx(); /* for modssl_get_app_data2() at request time */
434 
435     init_dh_params();
436 #if !MODSSL_USE_OPENSSL_PRE_1_1_API
437     init_bio_methods();
438 #endif
439 
440     return OK;
441 }
442 
443 /*
444  * Support for external a Crypto Device ("engine"), usually
445  * a hardware accellerator card for crypto operations.
446  */
447 #if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_INIT)
448 apr_status_t ssl_init_Engine(server_rec *s, apr_pool_t *p)
449 {
450     SSLModConfigRec *mc = myModConfig(s);
451     ENGINE *e;
452 
453     if (mc->szCryptoDevice) {
~~~

### modules/ssl/ssl_engine_kernel.c

~~~diff
--- a/modules/ssl/ssl_engine_kernel.c
+++ b/modules/ssl/ssl_engine_kernel.c
@@ -101,112 +101,28 @@ static int fill_reneg_buffer(request_rec
 }
 
 #ifdef HAVE_TLSEXT
-static int ap_array_same_str_set(apr_array_header_t *s1, apr_array_header_t *s2)
+/* Check whether a transition from vhost sc1 to sc2 from SNI to Host:
+ * vhost selection is permitted according to the SSLVHostSNIPolicy
+ * setting.  Returns 1 if the policy treats the vhosts as compatible,
+ * else 0. */
+static int ssl_check_vhost_sni_policy(SSLSrvConfigRec *sc1,
+                                      SSLSrvConfigRec *sc2)
 {
-    int i;
-    const char *c;
-    
-    if (s1 == s2) {
+    modssl_snivhpolicy_t policy = sc1->mc->snivh_policy;
+
+    /* Policy: insecure => allow everything. */
+    if (policy == MODSSL_SNIVH_INSECURE)
         return 1;
-    }
-    else if (!s1 || !s2 || (s1->nelts != s2->nelts)) {
-        return 0;
-    }
     
-    for (i = 0; i < s1->nelts; i++) {
-        c = APR_ARRAY_IDX(s1, i, const char *);
-        if (!c || !ap_array_str_contains(s2, c)) {
-            return 0;
-        }
-    }
-    return 1;
-}
-
-static int ssl_pk_server_compatible(modssl_pk_server_t *pks1, 
-                                    modssl_pk_server_t *pks2) 
-{
-    if (!pks1 || !pks2) {
-        return 0;
-    }
-    /* both have the same certificates? */
-    if ((pks1->ca_name_path != pks2->ca_name_path)
-        && (!pks1->ca_name_path || !pks2->ca_name_path 
-            || strcmp(pks1->ca_name_path, pks2->ca_name_path))) {
-        return 0;
-    }
-    if ((pks1->ca_name_file != pks2->ca_name_file)
-        && (!pks1->ca_name_file || !pks2->ca_name_file 
-            || strcmp(pks1->ca_name_file, pks2->ca_name_file))) {
-        return 0;
-    }
-    if (!ap_array_same_str_set(pks1->cert_files, pks2->cert_files)
-        || !ap_array_same_str_set(pks1->key_files, pks2->key_files)) {
-        return 0;
-    }
-    return 1;
-}
-
-static int ssl_auth_compatible(modssl_auth_ctx_t *a1, 
-                               modssl_auth_ctx_t *a2) 
-{
-    if (!a1 || !a2) {
-        return 0;
-    }
-    /* both have the same verification */
-    if ((a1->verify_depth != a2->verify_depth)
-        || (a1->verify_mode != a2->verify_mode)) {
+    /* Policy: strict => fail for any vhost transition. */
+    if (policy == MODSSL_SNIVH_STRICT && sc1 != sc2)
         return 0;
-    }
-    /* both have the same ca path/file */
-    if ((a1->ca_cert_path != a2->ca_cert_path)
-        && (!a1->ca_cert_path || !a2->ca_cert_path 
-            || strcmp(a1->ca_cert_path, a2->ca_cert_path))) {
-        return 0;
-    }
-    if ((a1->ca_cert_file != a2->ca_cert_file)
-        && (!a1->ca_cert_file || !a2->ca_cert_file 
-            || strcmp(a1->ca_cert_file, a2->ca_cert_file))) {
-        return 0;
-    }
-    /* both have the same ca cipher suite string */
-    if ((a1->cipher_suite != a2->cipher_suite)
-        && (!a1->cipher_suite || !a2->cipher_suite 
-            || strcmp(a1->cipher_suite, a2->cipher_suite))) {
-        return 0;
-    }
-    /* both have the same ca cipher suite string */
-    if ((a1->tls13_ciphers != a2->tls13_ciphers)
-        && (!a1->tls13_ciphers || !a2->tls13_ciphers 
-            || strcmp(a1->tls13_ciphers, a2->tls13_ciphers))) {
-        return 0;
-    }
-    return 1;
-}
 
-static int ssl_ctx_compatible(modssl_ctx_t *ctx1, 
-                              modssl_ctx_t *ctx2) 
-{
-    if (!ctx1 || !ctx2 
-        || (ctx1->protocol != ctx2->protocol)
-        || !ssl_auth_compatible(&ctx1->auth, &ctx2->auth)
-        || !ssl_pk_server_compatible(ctx1->pks, ctx2->pks)) {
-        return 0;
-    }
-    return 1;
-}
-
-static int ssl_server_compatible(server_rec *s1, server_rec *s2)
-{
-    SSLSrvConfigRec *sc1 = s1? mySrvConfig(s1) : NULL;
-    SSLSrvConfigRec *sc2 = s2? mySrvConfig(s2) : NULL;
+    /* For authonly/secure policy, compare the hash. */
+    AP_DEBUG_ASSERT(sc1->sni_policy_hash);
+    AP_DEBUG_ASSERT(sc2->sni_policy_hash);
 
-    /* both use the same TLS protocol? */
-    if (!sc1 || !sc2 
-        || !ssl_ctx_compatible(sc1->server, sc2->server)) {
-        return 0;
-    }
-    
-    return 1;
+    return strcmp(sc1->sni_policy_hash, sc2->sni_policy_hash) == 0;
 }
 #endif
 
@@ -275,6 +191,8 @@ int ssl_hook_ReadReq(request_rec *r)
         server_rec *handshakeserver = sslconn->server;
         SSLSrvConfigRec *hssc = mySrvConfig(handshakeserver);
 
+        AP_DEBUG_ASSERT(hssc);
+
         if ((servername = SSL_get_
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 93..124
93         rv = ssl_io_buffer_fill(r, rsize);
94     }
95     else {
96         /* If the reneg buffer size is set to zero, just fail. */
97         rv = HTTP_REQUEST_ENTITY_TOO_LARGE;
98     }
99 
100     return rv;
101 }
102 
103 #ifdef HAVE_TLSEXT
104 static int ap_array_same_str_set(apr_array_header_t *s1, apr_array_header_t *s2)
105 {
106     int i;
107     const char *c;
108     
109     if (s1 == s2) {
110         return 1;
111     }
112     else if (!s1 || !s2 || (s1->nelts != s2->nelts)) {
113         return 0;
114     }
115     
116     for (i = 0; i < s1->nelts; i++) {
117         c = APR_ARRAY_IDX(s1, i, const char *);
118         if (!c || !ap_array_str_contains(s2, c)) {
119             return 0;
120         }
121     }
122     return 1;
123 }
124 

Focal lines 267..298
267 #ifdef HAVE_TLSEXT
268     /*
269      * Perform SNI checks only on the initial request.  In particular,
270      * if these checks detect a problem, the checks shouldn't return an
271      * error again when processing an ErrorDocument redirect for the
272      * original problem.
273      */
274     if (r->proxyreq != PROXYREQ_PROXY && ap_is_initial_req(r)) {
275         server_rec *handshakeserver = sslconn->server;
276         SSLSrvConfigRec *hssc = mySrvConfig(handshakeserver);
277 
278         if ((servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))) {
279             /*
280              * The SNI extension supplied a hostname. So don't accept requests
281              * with either no hostname or a hostname that selected a different
282              * virtual host than the one used for the handshake, causing
283              * different SSL parameters to be applied, such as SSLProtocol,
284              * SSLCACertificateFile/Path and SSLCADNRequestFile/Path which
285              * cannot be renegotiated (SSLCA* due to current limitations in
286              * OpenSSL, see:
287              * http://mail-archives.apache.org/mod_mbox/httpd-dev/200806.mbox/%3C48592955.2090303@velox.ch%3E
288              * and
289              * http://mail-archives.apache.org/mod_mbox/httpd-dev/201312.mbox/%3CCAKQ1sVNpOrdiBm-UPw1hEdSN7YQXRRjeaT-MCWbW_7mN%3DuFiOw%40mail.gmail.com%3E
290              * )
291              */
292             if (!r->hostname) {
293                 ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02031)
294                             "Hostname %s provided via SNI, but no hostname"
295                             " provided in HTTP request", servername);
296                 return HTTP_BAD_REQUEST;
297             }
298         }

Focal lines 307..338
307              * This should avoid insecure configuration by accident.
308              */
309             ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02033)
310                          "No hostname was provided via SNI for a name based"
311                          " virtual host");
312             apr_table_setn(r->notes, "error-notes",
313                            "Reason: The client software did not provide a "
314                            "hostname using Server Name Indication (SNI), "
315                            "which is required to access this server.<br />\n");
316             return HTTP_FORBIDDEN;
317         }
318         if (r->server != handshakeserver
319             && !ssl_server_compatible(sslconn->server, r->server)) {
320             /*
321              * The request does not select the virtual host that was
322              * selected for handshaking and its SSL parameters are different
323              */
324 
325             ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02032)
326                          "Hostname %s %s and hostname %s provided"
327                          " via HTTP have no compatible SSL setup",
328                          servername ? servername : handshakeserver->server_hostname,
329                          servername ? "provided via SNI" : "(default host as no SNI was provided)",
330                          r->hostname);
331             return HTTP_MISDIRECTED_REQUEST;
332         }
333     }
334 #endif
335     modssl_set_app_data2(ssl, r);
336 
337     /*
338      * Log information about incoming HTTPS requests
~~~

### modules/ssl/ssl_private.h

~~~diff
--- a/modules/ssl/ssl_private.h
+++ b/modules/ssl/ssl_private.h
@@ -502,6 +502,19 @@ typedef struct {
     int          nBytes;
 } ssl_randseed_t;
 
+/* SNI vhost compatibility policy. */
+typedef enum {
+    MODSSL_SNIVH_STRICT   = 0,
+    MODSSL_SNIVH_SECURE   = 1,
+    MODSSL_SNIVH_AUTHONLY = 2,
+    MODSSL_SNIVH_INSECURE = 3
+} modssl_snivhpolicy_t;
+
+/* Maps modssl_snivhpolicy_t back into a config option string. */
+#define MODSSL_SNIVH_NAME(p_) ((p_) == MODSSL_SNIVH_STRICT ? "strict" : \
+                               ((p_) == MODSSL_SNIVH_SECURE ? "secure" : \
+                                ((p_) == MODSSL_SNIVH_AUTHONLY ? "authonly" : "insecure" )))
+
 /**
  * Define the structure of an ASN.1 anything
  */
@@ -628,6 +641,8 @@ typedef struct {
     /* Used for logging if SSLKEYLOGFILE is set at startup. */
     apr_file_t      *keylog_file;
 #endif
+
+    modssl_snivhpolicy_t snivh_policy;
 } SSLModConfigRec;
 
 /** Structure representing configured filenames for certs and keys for
@@ -782,6 +797,7 @@ struct SSLSrvConfigRec {
     modssl_ctx_t    *server;
 #ifdef HAVE_TLSEXT
     ssl_enabled_t    strict_sni_vhost_check;
+    const char      *sni_policy_hash;
 #endif
 #ifdef HAVE_FIPS
     BOOL             fips;
@@ -860,6 +876,7 @@ const char  *ssl_cmd_SSLRequire(cmd_parm
 const char  *ssl_cmd_SSLUserName(cmd_parms *, void *, const char *);
 const char  *ssl_cmd_SSLRenegBufferSize(cmd_parms *cmd, void *dcfg, const char *arg);
 const char  *ssl_cmd_SSLStrictSNIVHostCheck(cmd_parms *cmd, void *dcfg, int flag);
+const char  *ssl_cmd_SSLVHostSNIPolicy(cmd_parms *cmd, void *dcfg, const char *arg);
 const char *ssl_cmd_SSLInsecureRenegotiation(cmd_parms *cmd, void *dcfg, int flag);
 
 const char  *ssl_cmd_SSLProxyEngine(cmd_parms *cmd, void *dcfg, int flag);

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 494..525
494     int          nBytes;
495 } ssl_randseed_t;
496 
497 /**
498  * Define the structure of an ASN.1 anything
499  */
500 typedef struct {
501     long int       nData;
502     unsigned char *cpData;
503     apr_time_t     source_mtime;
504 } ssl_asn1_t;
505 
506 /**
507  * Define the mod_ssl per-module configuration structure
508  * (i.e. the global configuration for each httpd process)
509  */
510 
511 typedef struct SSLSrvConfigRec SSLSrvConfigRec;
512 typedef struct SSLDirConfigRec SSLDirConfigRec;
513 
514 typedef enum {
515     SSL_SHUTDOWN_TYPE_UNSET,
516     SSL_SHUTDOWN_TYPE_STANDARD,
517     SSL_SHUTDOWN_TYPE_UNCLEAN,
518     SSL_SHUTDOWN_TYPE_ACCURATE
519 } ssl_shutdown_type_e;
520 
521 typedef struct {
522     SSL *ssl;
523     const char *client_dn;
524     X509 *client_cert;
525     ssl_shutdown_type_e shutdown_type;

Focal lines 620..651
620 
621 /** Structure representing configured filenames for certs and keys for
622  * a given vhost */
623 typedef struct {
624     /* Lists of configured certs and keys for this server */
625     apr_array_header_t *cert_files;
626     apr_array_header_t *key_files;
627 
628     /** Certificates which specify the set of CA names which should be
629      * sent in the CertificateRequest message: */
630     const char  *ca_name_path;
631     const char  *ca_name_file;
632     
633     /* TLS service for this server is suspended */
634     int service_unavailable;
635 } modssl_pk_server_t;
636 
637 typedef struct {
638     /** proxy can have any number of cert/key pairs */
639     const char  *cert_file;
640     const char  *cert_path;
641     const char  *ca_cert_file;
642     STACK_OF(X509_INFO) *certs; /* Contains End Entity certs */
643     STACK_OF(X509) **ca_certs; /* Contains ONLY chain certs for
644                                 * each item in certs.
645                                 * (ptr to array of ptrs) */
646 } modssl_pk_proxy_t;
647 
648 /** stuff related to authentication that can also be per-dir */
649 typedef struct {
650     /** known/trusted CAs */
651     const char  *ca_cert_path;

Focal lines 774..805
774 };
775 
776 /**
777  * Define the mod_ssl per-directory configuration structure
778  * (i.e. the local configuration for all &lt;Directory>
779  *  and .htaccess contexts)
780  */
781 struct SSLDirConfigRec {
782     BOOL          bSSLRequired;
783     apr_array_header_t *aRequirement;
784     ssl_opt_t     nOptions;
785     ssl_opt_t     nOptionsAdd;
786     ssl_opt_t     nOptionsDel;
787     const char   *szCipherSuite;
788     ssl_verify_t  nVerifyClient;
789     int           nVerifyDepth;
790     const char   *szUserName;
791     apr_size_t    nRenegBufferSize;
792 
793     modssl_ctx_t *proxy;
794     BOOL          proxy_enabled;
795     BOOL          proxy_post_config;
796 };
797 
798 /**
799  *  function prototypes
800  */
801 
802 /**  API glue structures  */
803 extern module AP_MODULE_DECLARE_DATA ssl_module;
804 
805 /**  configuration handling   */
~~~

## CVE-2025-23048-regression-2.patch

Previous result: skipped

Touched paths: modules/ssl/ssl_engine_kernel.c

### Dry run fuzz=0 exit=1

~~~text
checking file modules/ssl/ssl_engine_kernel.c
Hunk #1 FAILED at 115.
1 out of 1 hunk FAILED

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file modules/ssl/ssl_engine_kernel.c
Hunk #1 FAILED at 115.
1 out of 1 hunk FAILED

~~~

### Dry run fuzz=2 exit=1

~~~text
checking file modules/ssl/ssl_engine_kernel.c
Hunk #1 FAILED at 115.
1 out of 1 hunk FAILED

~~~

### modules/ssl/ssl_engine_kernel.c

~~~diff
--- a/modules/ssl/ssl_engine_kernel.c
+++ b/modules/ssl/ssl_engine_kernel.c
@@ -115,8 +115,8 @@ static int ssl_check_vhost_sni_policy(SSLSrvConfigRec *sc1,
         return 1;
     
     /* Policy: strict => fail for any vhost transition. */
-    if (policy == MODSSL_SNIVH_STRICT && sc1 != sc2)
-        return 0;
+    if (policy == MODSSL_SNIVH_STRICT)
+        return sc1 == sc2;
 
     /* For authonly/secure policy, compare the hash. */
     AP_DEBUG_ASSERT(sc1->sni_policy_hash);

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 107..138
107     const char *c;
108     
109     if (s1 == s2) {
110         return 1;
111     }
112     else if (!s1 || !s2 || (s1->nelts != s2->nelts)) {
113         return 0;
114     }
115     
116     for (i = 0; i < s1->nelts; i++) {
117         c = APR_ARRAY_IDX(s1, i, const char *);
118         if (!c || !ap_array_str_contains(s2, c)) {
119             return 0;
120         }
121     }
122     return 1;
123 }
124 
125 static int ssl_pk_server_compatible(modssl_pk_server_t *pks1, 
126                                     modssl_pk_server_t *pks2) 
127 {
128     if (!pks1 || !pks2) {
129         return 0;
130     }
131     /* both have the same certificates? */
132     if ((pks1->ca_name_path != pks2->ca_name_path)
133         && (!pks1->ca_name_path || !pks2->ca_name_path 
134             || strcmp(pks1->ca_name_path, pks2->ca_name_path))) {
135         return 0;
136     }
137     if ((pks1->ca_name_file != pks2->ca_name_file)
138         && (!pks1->ca_name_file || !pks2->ca_name_file 
~~~

## CVE-2025-55753.patch

Previous result: skipped

Touched paths: modules/md/md.h, modules/md/md_acme.c, modules/md/md_acme.h, modules/md/md_acme_acct.c, modules/md/md_acme_authz.c, modules/md/md_acme_authz.h, modules/md/md_acme_drive.c, modules/md/md_acme_drive.h, modules/md/md_acme_order.c, modules/md/md_acme_order.h, modules/md/md_acmev2_drive.c, modules/md/md_core.c, modules/md/md_crypt.c, modules/md/md_crypt.h, modules/md/md_curl.c, modules/md/md_http.c, modules/md/md_http.h, modules/md/md_json.c, modules/md/md_log.h, modules/md/md_ocsp.c, modules/md/md_ocsp.h, modules/md/md_reg.c, modules/md/md_reg.h, modules/md/md_status.c, modules/md/md_status.h, modules/md/md_store.c, modules/md/md_store.h, modules/md/md_store_fs.c, modules/md/md_time.c, modules/md/md_time.h, modules/md/md_util.c, modules/md/md_util.h, modules/md/md_version.h, modules/md/mod_md.c, modules/md/mod_md.dsp, modules/md/mod_md.mak, modules/md/mod_md_config.c, modules/md/mod_md_config.h, modules/md/mod_md_drive.c, modules/md/mod_md_status.c

### Dry run fuzz=0 exit=1

~~~text
LED
checking file modules/md/md_time.h
Hunk #1 succeeded at 64 (offset -10 lines).
checking file modules/md/md_util.c
Hunk #1 succeeded at 148 (offset -108 lines).
Hunk #2 succeeded at 170 (offset -108 lines).
Hunk #3 succeeded at 217 (offset -108 lines).
Hunk #4 succeeded at 290 (offset -108 lines).
Hunk #5 succeeded at 751 (offset -108 lines).
Hunk #6 succeeded at 808 (offset -108 lines).
Hunk #7 succeeded at 918 (offset -108 lines).
Hunk #8 FAILED at 1081.
Hunk #9 succeeded at 1400 (offset -117 lines).
1 out of 9 hunks FAILED
checking file modules/md/md_util.h
Hunk #2 FAILED at 143.
Hunk #3 succeeded at 132 (offset -52 lines).
Hunk #4 succeeded at 152 (offset -52 lines).
1 out of 4 hunks FAILED
checking file modules/md/md_version.h
Hunk #1 FAILED at 27.
Hunk #2 FAILED at 35.
2 out of 2 hunks FAILED
checking file modules/md/mod_md.c
Hunk #1 succeeded at 94 (offset -4 lines).
Hunk #2 FAILED at 183.
Hunk #3 FAILED at 202.
Hunk #4 succeeded at 210 (offset -103 lines).
Hunk #5 FAILED at 331.
Hunk #6 FAILED at 363.
Hunk #7 succeeded at 257 (offset -120 lines).
Hunk #8 FAILED at 586.
Hunk #9 FAILED at 670.
Hunk #10 succeeded at 618 (offset -87 lines).
Hunk #11 FAILED at 713.
Hunk #12 FAILED at 886.
Hunk #13 FAILED at 929.
Hunk #14 FAILED at 1167.
Hunk #15 FAILED at 1247.
Hunk #16 FAILED at 1276.
Hunk #17 FAILED at 1359.
Hunk #18 FAILED at 1496.
14 out of 18 hunks FAILED
checking file modules/md/mod_md.dsp
Hunk #1 succeeded at 197 (offset -8 lines).
checking file modules/md/mod_md.mak
Hunk #1 succeeded at 79 (offset -1 lines).
Hunk #2 succeeded at 159 (offset -5 lines).
Hunk #3 succeeded at 236 (offset -5 lines).
Hunk #4 succeeded at 316 (offset -9 lines).
Hunk #5 succeeded at 556 (offset -13 lines).
checking file modules/md/mod_md_config.c
Hunk #1 FAILED at 26.
Hunk #2 FAILED at 83.
Hunk #3 FAILED at 106.
Hunk #4 FAILED at 160.
Hunk #5 FAILED at 180.
Hunk #6 FAILED at 200.
Hunk #7 FAILED at 211.
Hunk #8 FAILED at 246.
Hunk #9 FAILED at 254.
Hunk #10 succeeded at 227 (offset -42 lines).
Hunk #11 succeeded at 248 (offset -66 lines).
Hunk #12 succeeded at 271 (offset -66 lines).
Hunk #13 FAILED at 474.
Hunk #14 succeeded at 455 (offset -81 lines).
Hunk #15 succeeded at 475 (offset -81 lines).
Hunk #16 FAILED at 617.
Hunk #17 succeeded at 522 (offset -105 lines).
Hunk #18 FAILED at 757.
Hunk #19 FAILED at 948.
Hunk #20 FAILED at 973.
Hunk #21 FAILED at 1035.
Hunk #22 FAILED at 1185.
Hunk #23 FAILED at 1235.
Hunk #24 FAILED at 1284.
Hunk #25 FAILED at 1312.
Hunk #26 FAILED at 1371.
Hunk #27 succeeded at 1097 (offset -288 lines).
Hunk #28 FAILED at 1407.
21 out of 28 hunks FAILED
checking file modules/md/mod_md_config.h
Hunk #1 FAILED at 24.
Hunk #2 FAILED at 40.
Hunk #3 FAILED at 71.
Hunk #4 FAILED at 86.
4 out of 4 hunks FAILED
checking file modules/md/mod_md_drive.c
Hunk #1 FAILED at 100.
Hunk #2 FAILED at 125.
Hunk #3 FAILED at 154.
Hunk #4 succeeded at 329 (offset 149 lines).
Hunk #5 succeeded at 363 (offset 149 lines).
Hunk #6 FAILED at 341.
4 out of 6 hunks FAILED
checking file modules/md/mod_md_status.c
Hunk #2 succeeded at 54 (offset -1 lines).
Hunk #3 FAILED at 67.
Hunk #4 succeeded at 81 (offset -4 lines).
Hunk #5 succeeded at 90 (offset -5 lines).
Hunk #6 FAILED at 125.
Hunk #7 succeeded at 139 (offset -13 lines).
Hunk #8 FAILED at 182.
Hunk #9 FAILED at 198.
Hunk #10 FAILED at 219.
Hunk #11 FAILED at 234.
Hunk #12 FAILED at 244.
Hunk #13 FAILED at 270.
Hunk #14 FAILED at 327.
Hunk #15 FAILED at 411.
Hunk #16 FAILED at 426.
Hunk #17 FAILED at 434.
Hunk #18 FAILED at 463.
Hunk #19 succeeded at 407 (offset -71 lines).
Hunk #20 FAILED at 494.
Hunk #21 FAILED at 524.
Hunk #22 FAILED at 621.
Hunk #23 succeeded at 523 (offset -174 lines).
Hunk #24 FAILED at 705.
Hunk #25 succeeded at 542 (offset -174 lines).
17 out of 25 hunks FAILED

~~~

### Dry run fuzz=1 exit=1

~~~text

Hunk #1 succeeded at 148 (offset -108 lines).
Hunk #2 succeeded at 170 (offset -108 lines).
Hunk #3 succeeded at 217 (offset -108 lines).
Hunk #4 succeeded at 290 (offset -108 lines).
Hunk #5 succeeded at 751 (offset -108 lines).
Hunk #6 succeeded at 808 (offset -108 lines).
Hunk #7 succeeded at 918 (offset -108 lines).
Hunk #8 FAILED at 1081.
Hunk #9 succeeded at 1400 (offset -117 lines).
1 out of 9 hunks FAILED
checking file modules/md/md_util.h
Hunk #2 FAILED at 143.
Hunk #3 succeeded at 132 (offset -52 lines).
Hunk #4 succeeded at 152 (offset -52 lines).
1 out of 4 hunks FAILED
checking file modules/md/md_version.h
Hunk #1 FAILED at 27.
Hunk #2 FAILED at 35.
2 out of 2 hunks FAILED
checking file modules/md/mod_md.c
Hunk #1 succeeded at 94 (offset -4 lines).
Hunk #2 FAILED at 183.
Hunk #3 FAILED at 202.
Hunk #4 succeeded at 210 (offset -103 lines).
Hunk #5 FAILED at 331.
Hunk #6 FAILED at 363.
Hunk #7 succeeded at 257 (offset -120 lines).
Hunk #8 FAILED at 586.
Hunk #9 FAILED at 670.
Hunk #10 succeeded at 618 (offset -87 lines).
Hunk #11 FAILED at 713.
Hunk #12 FAILED at 886.
Hunk #13 FAILED at 929.
Hunk #14 FAILED at 1167.
Hunk #15 FAILED at 1247.
Hunk #16 FAILED at 1276.
Hunk #17 FAILED at 1359.
Hunk #18 FAILED at 1496.
14 out of 18 hunks FAILED
checking file modules/md/mod_md.dsp
Hunk #1 succeeded at 197 (offset -8 lines).
checking file modules/md/mod_md.mak
Hunk #1 succeeded at 79 (offset -1 lines).
Hunk #2 succeeded at 159 (offset -5 lines).
Hunk #3 succeeded at 236 (offset -5 lines).
Hunk #4 succeeded at 316 (offset -9 lines).
Hunk #5 succeeded at 556 (offset -13 lines).
checking file modules/md/mod_md_config.c
Hunk #1 succeeded at 26 with fuzz 1.
Hunk #2 FAILED at 84.
Hunk #3 FAILED at 107.
Hunk #4 FAILED at 161.
Hunk #5 FAILED at 181.
Hunk #6 succeeded at 170 with fuzz 1 (offset -31 lines).
Hunk #7 FAILED at 212.
Hunk #8 FAILED at 247.
Hunk #9 FAILED at 255.
Hunk #10 succeeded at 228 (offset -42 lines).
Hunk #11 succeeded at 249 (offset -66 lines).
Hunk #12 succeeded at 272 (offset -66 lines).
Hunk #13 FAILED at 475.
Hunk #14 succeeded at 456 (offset -81 lines).
Hunk #15 succeeded at 476 (offset -81 lines).
Hunk #16 succeeded at 513 with fuzz 1 (offset -105 lines).
Hunk #17 succeeded at 535 (offset -105 lines).
Hunk #18 FAILED at 770.
Hunk #19 FAILED at 961.
Hunk #20 FAILED at 986.
Hunk #21 FAILED at 1048.
Hunk #22 FAILED at 1198.
Hunk #23 FAILED at 1248.
Hunk #24 FAILED at 1297.
Hunk #25 FAILED at 1325.
Hunk #26 FAILED at 1384.
Hunk #27 succeeded at 1110 (offset -288 lines).
Hunk #28 FAILED at 1420.
18 out of 28 hunks FAILED
checking file modules/md/mod_md_config.h
Hunk #1 FAILED at 24.
Hunk #2 FAILED at 40.
Hunk #3 FAILED at 71.
Hunk #4 FAILED at 86.
4 out of 4 hunks FAILED
checking file modules/md/mod_md_drive.c
Hunk #1 FAILED at 100.
Hunk #2 FAILED at 125.
Hunk #3 FAILED at 154.
Hunk #4 succeeded at 329 (offset 149 lines).
Hunk #5 succeeded at 363 (offset 149 lines).
Hunk #6 FAILED at 341.
4 out of 6 hunks FAILED
checking file modules/md/mod_md_status.c
Hunk #2 succeeded at 54 (offset -1 lines).
Hunk #3 succeeded at 63 with fuzz 1 (offset -4 lines).
Hunk #4 succeeded at 81 (offset -4 lines).
Hunk #5 succeeded at 90 (offset -5 lines).
Hunk #6 FAILED at 125.
Hunk #7 succeeded at 139 (offset -13 lines).
Hunk #8 FAILED at 182.
Hunk #9 FAILED at 198.
Hunk #10 FAILED at 219.
Hunk #11 FAILED at 234.
Hunk #12 FAILED at 244.
Hunk #13 FAILED at 270.
Hunk #14 FAILED at 327.
Hunk #15 FAILED at 411.
Hunk #16 FAILED at 426.
Hunk #17 FAILED at 434.
Hunk #18 FAILED at 463.
Hunk #19 succeeded at 407 (offset -71 lines).
Hunk #20 FAILED at 494.
Hunk #21 FAILED at 524.
Hunk #22 FAILED at 621.
Hunk #23 succeeded at 523 (offset -174 lines).
Hunk #24 FAILED at 705.
Hunk #25 succeeded at 542 (offset -174 lines).
16 out of 25 hunks FAILED

~~~

### Dry run fuzz=2 exit=1

~~~text
217 (offset -108 lines).
Hunk #4 succeeded at 290 (offset -108 lines).
Hunk #5 succeeded at 751 (offset -108 lines).
Hunk #6 succeeded at 808 (offset -108 lines).
Hunk #7 succeeded at 918 (offset -108 lines).
Hunk #8 FAILED at 1081.
Hunk #9 succeeded at 1400 (offset -117 lines).
1 out of 9 hunks FAILED
checking file modules/md/md_util.h
Hunk #2 FAILED at 143.
Hunk #3 succeeded at 132 (offset -52 lines).
Hunk #4 succeeded at 152 (offset -52 lines).
1 out of 4 hunks FAILED
checking file modules/md/md_version.h
Hunk #1 FAILED at 27.
Hunk #2 FAILED at 35.
2 out of 2 hunks FAILED
checking file modules/md/mod_md.c
Hunk #1 succeeded at 94 (offset -4 lines).
Hunk #2 FAILED at 183.
Hunk #3 FAILED at 202.
Hunk #4 succeeded at 210 (offset -103 lines).
Hunk #5 FAILED at 331.
Hunk #6 succeeded at 264 with fuzz 2 (offset -99 lines).
Hunk #7 FAILED at 386.
Hunk #8 FAILED at 595.
Hunk #9 succeeded at 593 with fuzz 2 (offset -86 lines).
Hunk #10 succeeded at 629 (offset -87 lines).
Hunk #11 FAILED at 724.
Hunk #12 FAILED at 897.
Hunk #13 FAILED at 940.
Hunk #14 FAILED at 1178.
Hunk #15 FAILED at 1258.
Hunk #16 FAILED at 1287.
Hunk #17 FAILED at 1370.
Hunk #18 FAILED at 1507.
13 out of 18 hunks FAILED
checking file modules/md/mod_md.dsp
Hunk #1 succeeded at 197 (offset -8 lines).
checking file modules/md/mod_md.mak
Hunk #1 succeeded at 79 (offset -1 lines).
Hunk #2 succeeded at 159 (offset -5 lines).
Hunk #3 succeeded at 236 (offset -5 lines).
Hunk #4 succeeded at 316 (offset -9 lines).
Hunk #5 succeeded at 556 (offset -13 lines).
checking file modules/md/mod_md_config.c
Hunk #1 succeeded at 26 with fuzz 1.
Hunk #2 FAILED at 84.
Hunk #3 FAILED at 107.
Hunk #4 FAILED at 161.
Hunk #5 FAILED at 181.
Hunk #6 succeeded at 170 with fuzz 1 (offset -31 lines).
Hunk #7 FAILED at 212.
Hunk #8 FAILED at 247.
Hunk #9 FAILED at 255.
Hunk #10 succeeded at 228 (offset -42 lines).
Hunk #11 succeeded at 249 (offset -66 lines).
Hunk #12 succeeded at 272 (offset -66 lines).
Hunk #13 FAILED at 475.
Hunk #14 succeeded at 456 (offset -81 lines).
Hunk #15 succeeded at 476 (offset -81 lines).
Hunk #16 succeeded at 513 with fuzz 1 (offset -105 lines).
Hunk #17 succeeded at 535 (offset -105 lines).
Hunk #18 FAILED at 770.
Hunk #19 FAILED at 961.
Hunk #20 FAILED at 986.
Hunk #21 FAILED at 1048.
Hunk #22 FAILED at 1198.
Hunk #23 FAILED at 1248.
Hunk #24 FAILED at 1297.
Hunk #25 FAILED at 1325.
Hunk #26 FAILED at 1384.
Hunk #27 succeeded at 1110 (offset -288 lines).
Hunk #28 FAILED at 1420.
18 out of 28 hunks FAILED
checking file modules/md/mod_md_config.h
Hunk #1 FAILED at 24.
Hunk #2 FAILED at 40.
Hunk #3 FAILED at 71.
Hunk #4 FAILED at 86.
4 out of 4 hunks FAILED
checking file modules/md/mod_md_drive.c
Hunk #1 FAILED at 100.
Hunk #2 FAILED at 125.
Hunk #3 FAILED at 154.
Hunk #4 succeeded at 329 (offset 149 lines).
Hunk #5 succeeded at 363 (offset 149 lines).
Hunk #6 succeeded at 492 with fuzz 2 (offset 151 lines).
3 out of 6 hunks FAILED
checking file modules/md/mod_md_status.c
Hunk #2 succeeded at 54 (offset -1 lines).
Hunk #3 succeeded at 63 with fuzz 1 (offset -4 lines).
Hunk #4 succeeded at 81 (offset -4 lines).
Hunk #5 succeeded at 90 (offset -5 lines).
Hunk #6 FAILED at 125.
Hunk #7 succeeded at 139 (offset -13 lines).
Hunk #8 FAILED at 182.
Hunk #9 FAILED at 198.
Hunk #10 FAILED at 219.
Hunk #11 FAILED at 234.
Hunk #12 FAILED at 244.
Hunk #13 FAILED at 270.
Hunk #14 FAILED at 327.
Hunk #15 FAILED at 411.
Hunk #16 FAILED at 426.
Hunk #17 FAILED at 434.
Hunk #18 FAILED at 463.
Hunk #19 succeeded at 407 (offset -71 lines).
Hunk #20 FAILED at 494.
Hunk #21 FAILED at 524.
Hunk #22 FAILED at 621.
Hunk #23 succeeded at 523 (offset -174 lines).
Hunk #24 succeeded at 531 with fuzz 2 (offset -174 lines).
Hunk #25 succeeded at 542 (offset -174 lines).
15 out of 25 hunks FAILED

~~~

### modules/md/md.h

~~~diff
--- a/modules/md/md.h
+++ b/modules/md/md.h
@@ -78,37 +78,41 @@ struct md_t {
     struct apr_array_header_t *domains; /* all DNS names this MD includes */
     struct apr_array_header_t *contacts;   /* list of contact uris, e.g. mailto:xxx */
 
-    int transitive;                 /* != 0 iff VirtualHost names/aliases are auto-added */
-    md_require_t require_https;     /* Iff https: is required for this MD */
-    
-    int renew_mode;                 /* mode of obtaining credentials */
     struct md_pkeys_spec_t *pks;    /* specification for generating private keys */
-    int must_staple;                /* certificates should set the OCSP Must Staple extension */
     md_timeslice_t *renew_window;   /* time before expiration that starts renewal */
     md_timeslice_t *warn_window;    /* time before expiration that warnings are sent out */
     
-    const char *ca_url;             /* url of CA certificate service */
     const char *ca_proto;           /* protocol used vs CA (e.g. ACME) */
+    struct apr_array_header_t *ca_urls; /* urls of CAs */
+    const char *ca_effective;       /* url of CA used */
     const char *ca_account;         /* account used at CA */
     const char *ca_agreement;       /* accepted agreement uri between CA and user */
     struct apr_array_header_t *ca_challenges; /* challenge types configured for this MD */
     struct apr_array_header_t *cert_files; /* != NULL iff pubcerts explicitly configured */
     struct apr_array_header_t *pkey_files; /* != NULL iff privkeys explicitly configured */
     const char *ca_eab_kid;         /* optional KEYID for external account binding */
-    const char *ca_eab_hmac;        /* optional HMAC for external accont binding */
+    const char *ca_eab_hmac;        /* optional HMAC for external account binding */
+    const char *profile;            /* optional cert profile to order */
+    int profile_mandatory;          /* if profile, when given, is mandatory */
+    int ari_renewals;               /* if ACME ARI (RFC 9773) can trigger renewals */
 
-    md_state_t state;               /* state of this MD */
     const char *state_descr;        /* description of state of NULL */
     
     struct apr_array_header_t *acme_tls_1_domains; /* domains supporting "acme-tls/1" protocol */
-    int stapling;                   /* if OCSP stapling is enabled */
-    
-    int watched;               /* if certificate is supervised (renew or expiration warning) */
+    const char *dns01_cmd;          /* DNS challenge command, override global command */
+
     const struct md_srv_conf_t *sc; /* server config where it was defined or NULL */
     const char *defn_name;          /* config file this MD was defined */
     unsigned defn_line_number;      /* line number of definition */
-    
     const char *configured_name;    /* name this MD was configured with, if different */
+
+    int renew_mode;                 /* mode of obtaining credentials */
+    md_require_t require_https;     /* Iff https: is required for this MD */
+    md_state_t state;               /* state of this MD */
+    int transitive;                 /* != 0 iff VirtualHost names/aliases are auto-added */
+    int must_staple;                /* certificates should set the OCSP Must Staple extension */
+    int stapling;                   /* if OCSP stapling is enabled */
+    int watched;                    /* if certificate is supervised (renew or expiration warning) */
 };
 
 #define MD_KEY_ACCOUNT          "account"
@@ -116,6 +120,8 @@ struct md_t {
 #define MD_KEY_ACTIVATION_DELAY "activation-delay"
 #define MD_KEY_ACTIVITY         "activity"
 #define MD_KEY_AGREEMENT        "agreement"
+#define MD_KEY_ARI_CERT_ID      "ari-cert-id"
+#define MD_KEY_ARI_RENEWALS     "ari-renewals"
 #define MD_KEY_AUTHORIZATIONS   "authorizations"
 #define MD_KEY_BITS             "bits"
 #define MD_KEY_CA               "ca"
@@ -126,6 +132,7 @@ struct md_t {
 #define MD_KEY_CHALLENGE        "challenge"
 #define MD_KEY_CHALLENGES       "challenges"
 #define MD_KEY_CMD_DNS01        "cmd-dns-01"
+#define MD_KEY_DNS01_VERSION    "cmd-dns-01-version"
 #define MD_KEY_COMPLETE         "complete"
 #define MD_KEY_CONTACT          "contact"
 #define MD_KEY_CONTACTS         "contacts"
@@ -152,6 +159,8 @@ struct md_t {
 #define MD_KEY_HTTPS            "https"
 #define MD_KEY_ID               "id"
 #define MD_KEY_IDENTIFIER       "identifier"
+#define MD_KEY_ISSUER_NAME      "issuer-name"
+#define MD_KEY_ISSUER_URI   
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 70..101
70     MD_SG_NONE,
71     MD_SG_ACCOUNTS,
72     MD_SG_CHALLENGES,
73     MD_SG_DOMAINS,
74     MD_SG_STAGING,
75     MD_SG_ARCHIVE,
76     MD_SG_TMP,
77     MD_SG_COUNT,
78 } md_store_group_t;
79 
80 typedef enum {
81     MD_RENEW_DEFAULT = -1,          /* default value */
82     MD_RENEW_MANUAL,                /* manually triggered renewal of certificate */
83     MD_RENEW_AUTO,                  /* automatic process performed by httpd */
84     MD_RENEW_ALWAYS,                /* always renewed by httpd, even if not necessary */
85 } md_renew_mode_t;
86 
87 typedef struct md_t md_t;
88 struct md_t {
89     const char *name;               /* unique name of this MD */
90     struct apr_array_header_t *domains; /* all DNS names this MD includes */
91     struct apr_array_header_t *contacts;   /* list of contact uris, e.g. mailto:xxx */
92 
93     int transitive;                 /* != 0 iff VirtualHost names/aliases are auto-added */
94     md_require_t require_https;     /* Iff https: is required for this MD */
95     
96     int renew_mode;                 /* mode of obtaining credentials */
97     struct md_pkey_spec_t *pkey_spec;/* specification for generating new private keys */
98     int must_staple;                /* certificates should set the OCSP Must Staple extension */
99     const md_timeslice_t *renew_window;  /* time before expiration that starts renewal */
100     const md_timeslice_t *warn_window;   /* time before expiration that warnings are sent out */
101     

Focal lines 108..139
108     const char *pkey_file;          /* != NULL iff privkey file explicitly configured */
109     
110     md_state_t state;               /* state of this MD */
111     
112     struct apr_array_header_t *acme_tls_1_domains; /* domains supporting "acme-tls/1" protocol */
113     
114     const struct md_srv_conf_t *sc; /* server config where it was defined or NULL */
115     const char *defn_name;          /* config file this MD was defined */
116     unsigned defn_line_number;      /* line number of definition */
117     
118     const char *configured_name;    /* name this MD was configured with, if different */
119 };
120 
121 #define MD_KEY_ACCOUNT          "account"
122 #define MD_KEY_ACME_TLS_1       "acme-tls/1"
123 #define MD_KEY_ACTIVITY         "activity"
124 #define MD_KEY_AGREEMENT        "agreement"
125 #define MD_KEY_AUTHORIZATIONS   "authorizations"
126 #define MD_KEY_BITS             "bits"
127 #define MD_KEY_CA               "ca"
128 #define MD_KEY_CA_URL           "ca-url"
129 #define MD_KEY_CERT             "cert"
130 #define MD_KEY_CERT_FILE        "cert-file"
131 #define MD_KEY_CERTIFICATE      "certificate"
132 #define MD_KEY_CHALLENGE        "challenge"
133 #define MD_KEY_CHALLENGES       "challenges"
134 #define MD_KEY_CMD_DNS01        "cmd-dns-01"
135 #define MD_KEY_COMPLETE         "complete"
136 #define MD_KEY_CONTACT          "contact"
137 #define MD_KEY_CONTACTS         "contacts"
138 #define MD_KEY_CSR              "csr"
139 #define MD_KEY_DETAIL           "detail"

Focal lines 118..149
118     const char *configured_name;    /* name this MD was configured with, if different */
119 };
120 
121 #define MD_KEY_ACCOUNT          "account"
122 #define MD_KEY_ACME_TLS_1       "acme-tls/1"
123 #define MD_KEY_ACTIVITY         "activity"
124 #define MD_KEY_AGREEMENT        "agreement"
125 #define MD_KEY_AUTHORIZATIONS   "authorizations"
126 #define MD_KEY_BITS             "bits"
127 #define MD_KEY_CA               "ca"
128 #define MD_KEY_CA_URL           "ca-url"
129 #define MD_KEY_CERT             "cert"
130 #define MD_KEY_CERT_FILE        "cert-file"
131 #define MD_KEY_CERTIFICATE      "certificate"
132 #define MD_KEY_CHALLENGE        "challenge"
133 #define MD_KEY_CHALLENGES       "challenges"
134 #define MD_KEY_CMD_DNS01        "cmd-dns-01"
135 #define MD_KEY_COMPLETE         "complete"
136 #define MD_KEY_CONTACT          "contact"
137 #define MD_KEY_CONTACTS         "contacts"
138 #define MD_KEY_CSR              "csr"
139 #define MD_KEY_DETAIL           "detail"
140 #define MD_KEY_DISABLED         "disabled"
141 #define MD_KEY_DIR              "dir"
142 #define MD_KEY_DOMAIN           "domain"
143 #define MD_KEY_DOMAINS          "domains"
144 #define MD_KEY_ENTRIES          "entries"
145 #define MD_KEY_ERRORED          "errored"
146 #define MD_KEY_ERRORS           "errors"
147 #define MD_KEY_EXPIRES          "expires"
148 #define MD_KEY_FINALIZE         "finalize"
149 #define MD_KEY_FINISHED         "finished"
~~~

### modules/md/md_acme.c

~~~diff
--- a/modules/md/md_acme.c
+++ b/modules/md/md_acme.c
@@ -81,7 +81,7 @@ static apr_status_t problem_status_get(c
     }
      
     for(i = 0; i < (sizeof(Problems)/sizeof(Problems[0])); ++i) {
-        if (!apr_strnatcasecmp(type, Problems[i].type)) {
+        if (!apr_cstr_casecmp(type, Problems[i].type)) {
             return Problems[i].rv;
         }
     }
@@ -100,7 +100,7 @@ int md_acme_problem_is_input_related(con
     }
 
     for(i = 0; i < (sizeof(Problems)/sizeof(Problems[0])); ++i) {
-        if (!apr_strnatcasecmp(problem, Problems[i].type)) {
+        if (!apr_cstr_casecmp(problem, Problems[i].type)) {
             return Problems[i].input_related;
         }
     }
@@ -332,7 +332,7 @@ static apr_status_t acmev2_GET_as_POST_i
     return md_acme_req_body_init(req, NULL);
 }
 
-static apr_status_t md_acme_req_send(md_acme_req_t *req)
+static apr_status_t md_acme_req_send(md_acme_req_t *req, int get_as_post)
 {
     apr_status_t rv;
     md_acme_t *acme = req->acme;
@@ -352,7 +352,7 @@ static apr_status_t md_acme_req_send(md_
         if (APR_SUCCESS != rv) goto leave;
     }
     
-    if (!strcmp("GET", req->method) && !req->on_init && !req->req_json) {
+    if (get_as_post && !strcmp("GET", req->method) && !req->on_init && !req->req_json) {
         /* See <https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.6.3>
          * and <https://mailarchive.ietf.org/arch/msg/acme/sotffSQ0OWV-qQJodLwWYWcEVKI>
          * and <https://community.letsencrypt.org/t/acme-v2-scheduled-deprecation-of-unauthenticated-resource-gets/74380>
@@ -420,7 +420,7 @@ static apr_status_t md_acme_req_send(md_
     
     if (APR_EAGAIN == rv && req->max_retries > 0) {
         --req->max_retries;
-        rv = md_acme_req_send(req);
+        rv = md_acme_req_send(req, 1);
     }
     req = NULL;
 
@@ -449,14 +449,15 @@ apr_status_t md_acme_POST(md_acme_t *acm
     req->on_err = on_err;
     req->baton = baton;
     
-    return md_acme_req_send(req);
+    return md_acme_req_send(req, 1);
 }
 
 apr_status_t md_acme_GET(md_acme_t *acme, const char *url,
                          md_acme_req_init_cb *on_init,
                          md_acme_req_json_cb *on_json,
                          md_acme_req_res_cb *on_res,
-                          md_acme_req_err_cb *on_err,
+                         md_acme_req_err_cb *on_err,
+                         int get_as_post,
                          void *baton)
 {
     md_acme_req_t *req;
@@ -472,7 +473,7 @@ apr_status_t md_acme_GET(md_acme_t *acme
     req->on_err = on_err;
     req->baton = baton;
     
-    return md_acme_req_send(req);
+    return md_acme_req_send(req, get_as_post);
 }
 
 void md_acme_report_result(md_acme_t *acme, apr_status_t rv, struct md_result_t *result)
@@ -507,7 +508,7 @@ static apr_status_t on_got_json(md_acme_
 }
 
 apr_status_t md_acme_get_json(struct md_json_t **pjson, md_acme_t *acme, 
-                              const char *url, apr_pool_t *p)
+                              const char *url, int get_as_post, apr_pool_t *p)
 {
     apr_status_t rv;
     json_ctx ctx;
@@ -515,7 +516,7 @@ apr_status_t md_acme_get_json(struct md_
     ctx.pool = p;
     ctx.json = NULL;
     
-    rv = md_acme_GET(acme, url, NULL, on_got_json, NULL, NULL, &ctx);
+    rv = md_acme_GET(acme, url, NULL, on_got_json, NULL, NULL, get_as_post, &ctx);
     *pjson = (APR_SUCCESS == rv)? ctx.json : NULL;
     return rv;
 }
@@ -664,6 +665,15 @@ typedef struct {
     md_result_t *result;
 } update_dir_ctx;
 
+static int collect_profiles(void *baton, const char* key, md_json_t *json)
+{
+    update_dir_ctx *ctx = baton;
+    (void)json;
+    APR_ARRAY_PUSH(ctx->acme->api.v2.profiles, const char *) =
+        apr_pstrdup(ctx->acme->p, key);
+    return 1;
+}
+
 static apr_status_t update_directory(const md_http_response_t *res, void *data)
 {
     md_http_request_t *req = res->req;
@@ -711,10 +721,11 @@ static apr_status_t update_directory(con
         acme->api.v2.revoke_cert = md_json_dups(acme->p, json, "revokeCert", NULL);
         acme->api.v2.key_change = md_json_dups(acme->p, json, "keyChange", NULL);
         acme->api.v2.new_nonce = md_json_dups(acme->p, json, "newNonce", NULL);
+        acme->api.v2.renewal_info = md_json_dups(acme->p, json, "renewalInfo", NULL);
         /* RFC 8555 only requires "directory" and "newNonce" resources.
          * mod_md uses "newAccount" and "newOrder" so check for them.
          * But mod_md does not use the "revokeCert" 
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 73..104
73 
74     if (strstr(type, "urn:ietf:params:") == type) {
75         type += strlen("urn:ietf:params:");
76     }
77     else if (strstr(type, "urn:") == type) {
78         type += strlen("urn:");
79     }
80      
81     for(i = 0; i < (sizeof(Problems)/sizeof(Problems[0])); ++i) {
82         if (!apr_strnatcasecmp(type, Problems[i].type)) {
83             return Problems[i].rv;
84         }
85     }
86     return APR_EGENERAL;
87 }
88 
89 /**************************************************************************************************/
90 /* acme requests */
91 
92 static void req_update_nonce(md_acme_t *acme, apr_table_t *hdrs)
93 {
94     if (hdrs) {
95         const char *nonce = apr_table_get(hdrs, "Replay-Nonce");
96         if (nonce) {
97             acme->nonce = apr_pstrdup(acme->p, nonce);
98         }
99     }
100 }
101 
102 static apr_status_t http_update_nonce(const md_http_response_t *res)
103 {
104     if (res->headers) {

Focal lines 92..123
92 static void req_update_nonce(md_acme_t *acme, apr_table_t *hdrs)
93 {
94     if (hdrs) {
95         const char *nonce = apr_table_get(hdrs, "Replay-Nonce");
96         if (nonce) {
97             acme->nonce = apr_pstrdup(acme->p, nonce);
98         }
99     }
100 }
101 
102 static apr_status_t http_update_nonce(const md_http_response_t *res)
103 {
104     if (res->headers) {
105         const char *nonce = apr_table_get(res->headers, "Replay-Nonce");
106         if (nonce) {
107             md_acme_t *acme = res->req->baton;
108             acme->nonce = apr_pstrdup(acme->p, nonce);
109         }
110     }
111     return res->rv;
112 }
113 
114 static md_acme_req_t *md_acme_req_create(md_acme_t *acme, const char *method, const char *url)
115 {
116     apr_pool_t *pool;
117     md_acme_req_t *req;
118     apr_status_t rv;
119     
120     rv = apr_pool_create(&pool, acme->p);
121     if (rv != APR_SUCCESS) {
122         return NULL;
123     }

Focal lines 324..355
324         
325         if (!processed && req->on_res) {
326             processed = 1;
327             rv = req->on_res(req->acme, res, req->baton);
328         }
329         
330         if (!processed) {
331             rv = APR_EINVAL;
332             md_result_printf(req->result, rv, "unable to process the response: "
333                              "http-status=%d, content-type=%s", 
334                              res->status, apr_table_get(res->headers, "Content-Type"));
335             md_result_log(req->result, MD_LOG_ERR);
336         }
337     }
338     else if (APR_EAGAIN == (rv = inspect_problem(req, res))) {
339         /* leave req alive */
340         return rv;
341     }
342 
343 out:
344     md_acme_req_done(req, rv);
345     return rv;
346 }
347 
348 static apr_status_t acmev2_GET_as_POST_init(md_acme_req_t *req, void *baton)
349 {
350     (void)baton;
351     return md_acme_req_body_init(req, NULL);
352 }
353 
354 static apr_status_t md_acme_req_send(md_acme_req_t *req)
355 {
~~~

### modules/md/md_acme.h

~~~diff
--- a/modules/md/md_acme.h
+++ b/modules/md/md_acme.h
@@ -118,6 +118,8 @@ struct md_acme_t {
             const char *key_change;
             const char *revoke_cert;
             const char *new_nonce;
+            const char *renewal_info;
+            struct apr_array_header_t *profiles;
         } v2;
     } api;
     const char *ca_agreement;
@@ -274,6 +276,7 @@ apr_status_t md_acme_GET(md_acme_t *acme
                          md_acme_req_json_cb *on_json,
                          md_acme_req_res_cb *on_res,
                          md_acme_req_err_cb *on_err,
+                         int get_as_post,
                          void *baton);
 /**
  * Perform a POST against the ACME url. If a on_json callback is given and
@@ -300,7 +303,7 @@ apr_status_t md_acme_POST(md_acme_t *acm
  * Retrieve a JSON resource from the ACME server 
  */
 apr_status_t md_acme_get_json(struct md_json_t **pjson, md_acme_t *acme, 
-                              const char *url, apr_pool_t *p);
+                              const char *url, int get_as_post, apr_pool_t *p);
 
 
 apr_status_t md_acme_req_body_init(md_acme_req_t *req, struct md_json_t *jpayload);

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 110..141
110             const char *new_reg;
111             const char *revoke_cert;
112             
113         } v1;
114         struct {
115             const char *new_account;
116             const char *new_order;
117             const char *key_change;
118             const char *revoke_cert;
119             const char *new_nonce;
120         } v2;
121     } api;
122     const char *ca_agreement;
123     const char *acct_name;
124     
125     md_acme_new_nonce_fn *new_nonce_fn;
126     md_acme_req_init_fn *req_init_fn;
127     md_acme_post_fn *post_new_account_fn;
128     
129     struct md_http_t *http;
130     
131     const char *nonce;
132     int max_retries;
133     struct md_result_t *last;      /* result of last request */
134 };
135 
136 /**
137  * Global init, call once at start up.
138  */
139 apr_status_t md_acme_init(apr_pool_t *pool, const char *base_version, int init_ssl);
140 
141 /**

Focal lines 266..291
266  * @param acme        the ACME server to talk to
267  * @param url         the url to send the request to
268  * @param on_init     callback to initialize the request data
269  * @param on_json     callback on successful JSON response
270  * @param on_res      callback on successful HTTP response
271  * @param baton       userdata for callbacks
272  */
273 apr_status_t md_acme_POST(md_acme_t *acme, const char *url,
274                           md_acme_req_init_cb *on_init,
275                           md_acme_req_json_cb *on_json,
276                           md_acme_req_res_cb *on_res,
277                           md_acme_req_err_cb *on_err,
278                           void *baton);
279 
280 /**
281  * Retrieve a JSON resource from the ACME server 
282  */
283 apr_status_t md_acme_get_json(struct md_json_t **pjson, md_acme_t *acme, 
284                               const char *url, apr_pool_t *p);
285 
286 
287 apr_status_t md_acme_req_body_init(md_acme_req_t *req, struct md_json_t *jpayload);
288 
289 apr_status_t md_acme_protos_add(struct apr_hash_t *protos, apr_pool_t *p);
290 
291 #endif /* md_acme_h */

Focal lines 292..291

~~~

### modules/md/md_acme_acct.c

~~~diff
--- a/modules/md/md_acme_acct.c
+++ b/modules/md/md_acme_acct.c
@@ -243,7 +243,7 @@ int md_acme_acct_matches_url(md_acme_acc
 
 int md_acme_acct_matches_md(md_acme_acct_t *acct, const md_t *md)
 {
-    if (!md_acme_acct_matches_url(acct, md->ca_url)) return 0;
+    if (!md_acme_acct_matches_url(acct, md->ca_effective)) return 0;
     /* if eab values are not mentioned, we match an account regardless
      * if it was registered with eab or not */
     if (!md->ca_eab_kid || !md->ca_eab_hmac) {
@@ -285,7 +285,7 @@ static int find_acct(void *baton, const
             && (!ctx->md || md_acme_acct_matches_md(acct, ctx->md))) {
             md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ctx->p, 
                           "found account %s for %s: %s, status=%d",
-                          acct->id, ctx->md->ca_url, aspect, acct->status);
+                          acct->id, ctx->md->ca_effective, aspect, acct->status);
             ctx->id = apr_pstrdup(ctx->p, name);
             return 0;
         }

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 235..266
235 /* Lookup */
236 
237 typedef struct {
238     apr_pool_t *p;
239     md_acme_t *acme;
240     int url_match;
241     const char *id;
242 } find_ctx;
243 
244 static int find_acct(void *baton, const char *name, const char *aspect,
245                      md_store_vtype_t vtype, void *value, apr_pool_t *ptemp)
246 {
247     find_ctx *ctx = baton;
248     int disabled;
249     const char *ca_url, *status;
250     
251     (void)aspect;
252     (void)ptemp;
253     md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ctx->p, "account candidate %s/%s", name, aspect); 
254     if (MD_SV_JSON == vtype) {
255         md_json_t *json = value;
256         
257         status = md_json_gets(json, MD_KEY_STATUS, NULL);
258         disabled = md_json_getb(json, MD_KEY_DISABLED, NULL);
259         ca_url = md_json_gets(json, MD_KEY_CA_URL, NULL);
260         
261         if ((!status || !strcmp("valid", status)) && !disabled 
262             && (!ctx->url_match || (ca_url && !strcmp(ctx->acme->url, ca_url)))) {
263             md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ctx->p, 
264                           "found account %s for %s: %s, status=%s, disabled=%d, ca-url=%s", 
265                           name, ctx->acme->url, aspect, status, disabled, ca_url);
266             ctx->id = apr_pstrdup(ctx->p, name);

Focal lines 277..308
277 {
278     apr_status_t rv;
279     find_ctx ctx;
280     
281     ctx.p = p;
282     ctx.acme = acme;
283     ctx.id = NULL;
284     ctx.url_match = url_match;
285     *pid = NULL;
286     
287     rv = md_store_iter(find_acct, &ctx, store, p, group, name_pattern, MD_FN_ACCOUNT, MD_SV_JSON);
288     if (ctx.id) {
289         *pid = ctx.id;
290         rv = md_acme_acct_load(pacct, ppkey, store, group, ctx.id, p);
291         md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "loading account %s", ctx.id);
292     }
293     else {
294         *pacct = NULL;
295         rv = APR_ENOENT;
296         md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, p, "acct_find: none found"); 
297     }
298     return rv;
299 }
300 
301 static apr_status_t acct_find_and_verify(md_store_t *store, md_store_group_t group, 
302                                          const char *name_pattern, md_acme_t *acme, apr_pool_t *p)
303 {
304     md_acme_acct_t *acct;
305     md_pkey_t *pkey;
306     const char *id;
307     apr_status_t rv;
308 
~~~

### modules/md/md_acme_authz.c

~~~diff
--- a/modules/md/md_acme_authz.c
+++ b/modules/md/md_acme_authz.c
@@ -131,7 +131,7 @@ apr_status_t md_acme_authz_update(md_acm
     err = "unable to parse response";
     log_level = MD_LOG_ERR;
     
-    if (APR_SUCCESS == (rv = md_acme_get_json(&json, acme, authz->url, p))
+    if (APR_SUCCESS == (rv = md_acme_get_json(&json, acme, authz->url, 1, p))
         && (s = md_json_gets(json, MD_KEY_STATUS, NULL))) {
             
         authz->domain = md_json_gets(json, MD_KEY_IDENTIFIER, MD_KEY_VALUE, NULL); 
@@ -243,8 +243,9 @@ static apr_status_t setup_key_authz(md_a
 static apr_status_t cha_http_01_setup(md_acme_authz_cha_t *cha, md_acme_authz_t *authz,
                                       md_acme_t *acme, md_store_t *store, 
                                       md_pkeys_spec_t *key_specs,
-                                      apr_array_header_t *acme_tls_1_domains, const char *mdomain,
-                                      apr_table_t *env, md_result_t *result, apr_pool_t *p)
+                                      apr_array_header_t *acme_tls_1_domains, const md_t *md,
+                                      apr_table_t *env, md_result_t *result,
+                                      const char **psetup_token, apr_pool_t *p)
 {
     const char *data;
     apr_status_t rv;
@@ -253,7 +254,7 @@ static apr_status_t cha_http_01_setup(md
     (void)key_specs;
     (void)env;
     (void)acme_tls_1_domains;
-    (void)mdomain;
+    (void)md;
 
     if (APR_SUCCESS != (rv = setup_key_authz(cha, authz, acme, p, &notify_server))) {
         goto out;
@@ -262,9 +263,8 @@ static apr_status_t cha_http_01_setup(md
     rv = md_store_load(store, MD_SG_CHALLENGES, authz->domain, MD_FN_HTTP01,
                        MD_SV_TEXT, (void**)&data, p);
     if ((APR_SUCCESS == rv && strcmp(cha->key_authz, data)) || APR_STATUS_IS_ENOENT(rv)) {
-        const char *content = apr_psprintf(p, "%s\n", cha->key_authz);
         rv = md_store_save(store, p, MD_SG_CHALLENGES, authz->domain, MD_FN_HTTP01,
-                           MD_SV_TEXT, (void*)content, 0);
+                           MD_SV_TEXT, (void*)cha->key_authz, 0);
         notify_server = 1;
     }
     
@@ -289,6 +289,8 @@ static apr_status_t cha_http_01_setup(md
         rv = md_acme_POST(acme, cha->uri, on_init_authz_resp, authz_http_set, NULL, NULL, &ctx);
     }
 out:
+    *psetup_token = (APR_SUCCESS == rv)?
+        apr_psprintf(p, "%s:%s", MD_AUTHZ_TYPE_HTTP01, authz->domain) : NULL;
     return rv;
 }
 
@@ -301,8 +303,9 @@ void tls_alpn01_fnames(apr_pool_t *p, md
 static apr_status_t cha_tls_alpn_01_setup(md_acme_authz_cha_t *cha, md_acme_authz_t *authz, 
                                           md_acme_t *acme, md_store_t *store, 
                                           md_pkeys_spec_t *key_specs,
-                                          apr_array_header_t *acme_tls_1_domains, const char *mdomain,
-                                          apr_table_t *env, md_result_t *result, apr_pool_t *p)
+                                          apr_array_header_t *acme_tls_1_domains, const md_t *md,
+                                          apr_table_t *env, md_result_t *result,
+                                          const char **psetup_token, apr_pool_t *p)
 {
     const char *acme_id, *token;
     apr_status_t rv;
@@ -311,7 +314,7 @@ static apr_status_t cha_tls_alpn_01_setu
     int i;
 
     (void)env;
-    (void)mdomain;
+    (void)md;
     if (md_array_str_index(acme_tls_1_domains, authz->domain, 0, 0) < 0) {
         rv = APR_ENOTIMPL;
         if (acme_tls_1_domains->nelts) {
@@ -334,7 +337,7 @@ static apr_status_t cha_tls_alpn_01_setu
 
     /* Create a "tls-alpn-01" certificate for the domain we want to authenticate.
      * The server will need to answer a TLS connection with SNI == authz->domain
-     * and ALPN procotol "acme-tls/1" with this certificate.
+     * and ALPN protocol "acme-tls/1" with this certificate.
      */
     md_data_init_str(&data, cha->key_authz);
     rv = md_crypt_sha256_digest_hex(&token, p, &data);
@@ -407,14 +410,17 @@ static apr_status_t cha_tls_alpn_01_setu
         rv = md_acme_POST(acme, cha->uri, on_init_authz_resp, authz_http_set, NULL, NULL, &ctx);
     }
 out:    
+    *psetup_token = (APR_SUCCESS == rv)?
+        apr_psprintf(p, "%s:%s", MD_AUTHZ_TYPE_TLSALPN01, authz->domain) : NULL;
     return rv;
 }
 
 static apr_status_t cha_dns_01_setup(md_acme_authz_cha_t *cha, md_acme_authz_t *authz, 
                   
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 123..154
123     md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->p, "create new authz");
124     rv = md_acme_POST(acme, acme->api.v1.new_authz, on_init_authz, authz_created, NULL, NULL, &ctx);
125     
126     *pauthz = (APR_SUCCESS == rv)? ctx.authz : NULL;
127     return rv;
128 }
129 
130 /**************************************************************************************************/
131 /* Update an existing authorization */
132 
133 apr_status_t md_acme_authz_retrieve(md_acme_t *acme, apr_pool_t *p, const char *url, 
134                                     md_acme_authz_t **pauthz)
135 {
136     md_acme_authz_t *authz;
137     apr_status_t rv;
138     
139     authz = apr_pcalloc(p, sizeof(*authz));
140     authz->url = apr_pstrdup(p, url);
141     rv = md_acme_authz_update(authz, acme, p);
142     
143     *pauthz = (APR_SUCCESS == rv)? authz : NULL;
144     return rv;
145 }
146 
147 apr_status_t md_acme_authz_update(md_acme_authz_t *authz, md_acme_t *acme, apr_pool_t *p)
148 {
149     md_json_t *json;
150     const char *s, *err;
151     md_log_level_t log_level;
152     apr_status_t rv;
153     
154     assert(acme);

Focal lines 235..266
235 } 
236 
237 static apr_status_t authz_http_set(md_acme_t *acme, apr_pool_t *p, const apr_table_t *hdrs, 
238                                    md_json_t *body, void *baton)
239 {
240     authz_req_ctx *ctx = baton;
241     
242     (void)acme;
243     (void)p;
244     (void)hdrs;
245     (void)body;
246     md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, ctx->p, "updated authz %s", ctx->authz->url);
247     return APR_SUCCESS;
248 }
249 
250 static apr_status_t setup_key_authz(md_acme_authz_cha_t *cha, md_acme_authz_t *authz,
251                                     md_acme_t *acme, apr_pool_t *p, int *pchanged)
252 {
253     const char *thumb64, *key_authz;
254     apr_status_t rv;
255     
256     (void)authz;
257     assert(cha);
258     assert(cha->token);
259     
260     *pchanged = 0;
261     if (APR_SUCCESS == (rv = md_jws_pkey_thumb(&thumb64, p, acme->acct_key))) {
262         key_authz = apr_psprintf(p, "%s.%s", cha->token, thumb64);
263         if (cha->key_authz) {
264             if (strcmp(key_authz, cha->key_authz)) {
265                 /* Hu? Did the account change key? */
266                 cha->key_authz = NULL;

Focal lines 245..276
245     (void)body;
246     md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, ctx->p, "updated authz %s", ctx->authz->url);
247     return APR_SUCCESS;
248 }
249 
250 static apr_status_t setup_key_authz(md_acme_authz_cha_t *cha, md_acme_authz_t *authz,
251                                     md_acme_t *acme, apr_pool_t *p, int *pchanged)
252 {
253     const char *thumb64, *key_authz;
254     apr_status_t rv;
255     
256     (void)authz;
257     assert(cha);
258     assert(cha->token);
259     
260     *pchanged = 0;
261     if (APR_SUCCESS == (rv = md_jws_pkey_thumb(&thumb64, p, acme->acct_key))) {
262         key_authz = apr_psprintf(p, "%s.%s", cha->token, thumb64);
263         if (cha->key_authz) {
264             if (strcmp(key_authz, cha->key_authz)) {
265                 /* Hu? Did the account change key? */
266                 cha->key_authz = NULL;
267             }
268         }
269         if (!cha->key_authz) {
270             cha->key_authz = key_authz;
271             *pchanged = 1;
272         }
273     }
274     return rv;
275 }
276 
~~~

### modules/md/md_acme_authz.h

~~~diff
--- a/modules/md/md_acme_authz.h
+++ b/modules/md/md_acme_authz.h
@@ -68,12 +68,12 @@ apr_status_t md_acme_authz_update(md_acm
 apr_status_t md_acme_authz_respond(md_acme_authz_t *authz, struct md_acme_t *acme, 
                                    struct md_store_t *store, apr_array_header_t *challenges, 
                                    struct md_pkeys_spec_t *key_spec,
-                                   apr_array_header_t *acme_tls_1_domains, const char *mdomain,
+                                   apr_array_header_t *acme_tls_1_domains, const md_t *md,
                                    struct apr_table_t *env,
                                    apr_pool_t *p, const char **setup_token,
                                    struct md_result_t *result);
 
 apr_status_t md_acme_authz_teardown(struct md_store_t *store, const char *setup_token, 
-                                    const char *mdomain, struct apr_table_t *env, apr_pool_t *p);
+                                    const md_t *md, struct apr_table_t *env, apr_pool_t *p);
 
 #endif /* md_acme_authz_h */

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 60..83
60 
61 
62 md_acme_authz_t *md_acme_authz_create(apr_pool_t *p);
63 
64 /* authz interaction with ACME server */
65 apr_status_t md_acme_authz_register(struct md_acme_authz_t **pauthz, struct md_acme_t *acme,
66                                     const char *domain, apr_pool_t *p);
67 
68 apr_status_t md_acme_authz_retrieve(md_acme_t *acme, apr_pool_t *p, const char *url, 
69                                     md_acme_authz_t **pauthz);
70 apr_status_t md_acme_authz_update(md_acme_authz_t *authz, struct md_acme_t *acme, apr_pool_t *p);
71 
72 apr_status_t md_acme_authz_respond(md_acme_authz_t *authz, struct md_acme_t *acme, 
73                                    struct md_store_t *store, apr_array_header_t *challenges, 
74                                    struct md_pkey_spec_t *key_spec,
75                                    apr_array_header_t *acme_tls_1_domains, 
76                                    struct apr_table_t *env,
77                                    apr_pool_t *p, const char **setup_token,
78                                    struct md_result_t *result);
79 
80 apr_status_t md_acme_authz_teardown(struct md_store_t *store, const char *setup_token, 
81                                     struct apr_table_t *env, apr_pool_t *p);
82 
83 #endif /* md_acme_authz_h */
~~~

### modules/md/md_acme_drive.c

~~~diff
--- a/modules/md/md_acme_drive.c
+++ b/modules/md/md_acme_drive.c
@@ -45,7 +45,7 @@
 /**************************************************************************************************/
 /* account setup */
 
-static apr_status_t use_staged_acct(md_acme_t *acme, struct md_store_t *store, 
+static apr_status_t use_staged_acct(md_acme_t *acme, struct md_store_t *store,
                                     const md_t *md, apr_pool_t *p)
 {
     md_acme_acct_t *acct;
@@ -256,7 +256,7 @@ static apr_status_t get_cert(void *baton
     (void)attempt;
     md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, d->p, "retrieving cert from %s",
                   ad->order->certificate);
-    return md_acme_GET(ad->acme, ad->order->certificate, NULL, NULL, on_add_cert, NULL, d);
+    return md_acme_GET(ad->acme, ad->order->certificate, NULL, NULL, on_add_cert, NULL, 1, d);
 }
 
 apr_status_t md_acme_drive_cert_poll(md_proto_driver_t *d, int only_once)
@@ -305,11 +305,11 @@ static apr_status_t csr_req(md_acme_t *a
     
     (void)acme;
     location = apr_table_get(res->headers, "location");
-    if (!location) {
-        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, d->p, 
-                      "cert created without giving its location header");
-        return APR_EINVAL;
-    }
+    if (!location)
+      return rv;
+
+    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p,
+                  "cert created with location header (old ACMEv1 style)");
     ad->order->certificate = apr_pstrdup(d->p, location);
     if (APR_SUCCESS != (rv = md_acme_order_save(d->store, d->p, MD_SG_STAGING, 
                                                 d->md->name, ad->order, 0))) { 
@@ -429,7 +429,7 @@ static apr_status_t get_chain(void *bato
 
             md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, 
                           "next chain cert at  %s", ad->chain_up_link);
-            rv = md_acme_GET(ad->acme, ad->chain_up_link, NULL, NULL, on_add_chain, NULL, d);
+            rv = md_acme_GET(ad->acme, ad->chain_up_link, NULL, NULL, on_add_chain, NULL, 1, d);
             
             if (APR_SUCCESS == rv && nelts == ad->cred->chain->nelts) {
                 break;
@@ -515,8 +515,8 @@ static apr_status_t acme_driver_preload_
     d->baton = ad;
     
     ad->driver = d;
-    ad->authz_monitor_timeout = apr_time_from_sec(30);
-    ad->cert_poll_timeout = apr_time_from_sec(30);
+    ad->authz_monitor_timeout = apr_time_from_sec(300);
+    ad->cert_poll_timeout = apr_time_from_sec(300);
     ad->ca_challenges = apr_array_make(d->p, 3, sizeof(const char*));
     
     /* We want to obtain credentials (key+certificate) for every key spec in this MD */
@@ -587,7 +587,9 @@ static apr_status_t acme_driver_init(md_
             ad->ca_challenges = md_array_str_remove(d->p, ad->ca_challenges, MD_AUTHZ_TYPE_TLSALPN01, 0);
             dis_alpn_acme = 1;
         }
-        if (!apr_table_get(d->env, MD_KEY_CMD_DNS01) && md_array_str_index(ad->ca_challenges, MD_AUTHZ_TYPE_DNS01, 0, 1) >= 0) {
+        if (!apr_table_get(d->env, MD_KEY_CMD_DNS01)
+            && NULL == d->md->dns01_cmd
+            && md_array_str_index(ad->ca_challenges, MD_AUTHZ_TYPE_DNS01, 0, 1) >= 0) {
             ad->ca_challenges = md_array_str_remove(d->p, ad->ca_challenges, MD_AUTHZ_TYPE_DNS01, 0);
             dis_dns = 1;
         }
@@ -654,13 +656,15 @@ static apr_status_t acme_renew(md_proto_
     apr_status_t rv = APR_SUCCESS;
     apr_time_t now, t, t2;
     md_credentials_t *cred;
+    const char *ca_effective = NULL;
     char ts[APR_RFC822_DATE_LEN];
     int i, first = 0;
-    
-    if (md_log_is_level(d->p, MD_LOG_DEBUG)) {
-        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, "%s: staging started, "
-                      "state=%d, challenges='%s'", d->md->name, d->md->state, 
-                      apr_array_pstrcat(d->p, ad->ca_challenges, ' '));
+
+    if (!d->md->ca_urls || d->md->ca_urls->nelts <= 0) {
+        /* No CA defined? This is checked in several other places, but lets be sure */
+        md_result_printf(result, APR_INCOMPLETE,
+            "The managed domain %s is missing MDCertificateAuthority", d->md->name);
+        goto out;
     }
 
     /* When not explicitly told to reset, we check the existing data. If
@@ -679,13 +683,46 @@ static apr_status_t acme_renew(md_proto_
             rv = APR_SUCCESS;
         }
     }
-    
+
+    /* What CA are we using this time? */
+    if (ad->md && ad->md->ca_effective) {
+        /* There was one
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 37..68
37 #include "md_acme.h"
38 #include "md_acme_acct.h"
39 #include "md_acme_authz.h"
40 #include "md_acme_order.h"
41 
42 #include "md_acme_drive.h"
43 #include "md_acmev1_drive.h"
44 #include "md_acmev2_drive.h"
45 
46 /**************************************************************************************************/
47 /* account setup */
48 
49 static apr_status_t use_staged_acct(md_acme_t *acme, struct md_store_t *store, 
50                                     const char *md_name, apr_pool_t *p)
51 {
52     md_acme_acct_t *acct;
53     md_pkey_t *pkey;
54     apr_status_t rv;
55     
56     if (APR_SUCCESS == (rv = md_acme_acct_load(&acct, &pkey, store, 
57                                                MD_SG_STAGING, md_name, acme->p))) {
58         acme->acct_id = NULL;
59         acme->acct = acct;
60         acme->acct_key = pkey;
61         rv = md_acme_acct_validate(acme, NULL, p);
62     }
63     return rv;
64 }
65 
66 static apr_status_t save_acct_staged(md_acme_t *acme, md_store_t *store, 
67                                      const char *md_name, apr_pool_t *p)
68 {

Focal lines 248..279
248     assert(ad->order);
249     assert(ad->order->certificate);
250     
251     if (only_once) {
252         rv = get_cert(d, 0);
253     }
254     else {
255         rv = md_util_try(get_cert, d, 1, ad->cert_poll_timeout, 0, 0, 1);
256     }
257     
258     md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, "poll for cert at %s", ad->order->certificate);
259     return rv;
260 }
261 
262 /**************************************************************************************************/
263 /* order finalization */
264 
265 static apr_status_t on_init_csr_req(md_acme_req_t *req, void *baton)
266 {
267     md_proto_driver_t *d = baton;
268     md_acme_driver_t *ad = d->baton;
269     md_json_t *jpayload;
270 
271     jpayload = md_json_create(req->p);
272     if (MD_ACME_VERSION_MAJOR(req->acme->version) == 1) {
273         md_json_sets("new-cert", jpayload, MD_KEY_RESOURCE, NULL);
274     }
275     md_json_sets(ad->csr_der_64, jpayload, MD_KEY_CSR, NULL);
276     
277     return md_acme_req_body_init(req, jpayload);
278 } 
279 

Focal lines 297..328
297                                                 d->md->name, ad->order, 0))) { 
298         md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, d->p, 
299                       "%s: saving cert url %s", d->md->name, location);
300         return rv;
301     }
302     
303     /* Check if it already was sent with this response */
304     ad->next_up_link = NULL;
305     if (APR_SUCCESS == (rv = md_cert_read_http(&cert, d->p, res))) {
306         md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "cert parsed");
307         apr_array_clear(ad->certs);
308         APR_ARRAY_PUSH(ad->certs, md_cert_t*) = cert;
309         get_up_link(d, res->headers);
310     }
311     else if (APR_STATUS_IS_ENOENT(rv)) {
312         rv = APR_SUCCESS;
313         if (location) {
314             md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, 
315                           "cert not in response, need to poll %s", location);
316         }
317     }
318     
319     return rv;
320 }
321 
322 /**
323  * Pre-Req: all domains have been validated by the ACME server, e.g. all have AUTHZ
324  * resources that have status 'valid'
325  * - Setup private key, if not already there
326  * - Generate a CSR with org, contact, etc
327  * - Optionally enable must-staple OCSP extension
328  * - Submit CSR, expect 201 with location
~~~

### modules/md/md_acme_drive.h

~~~diff
--- a/modules/md/md_acme_drive.h
+++ b/modules/md/md_acme_drive.h
@@ -29,6 +29,8 @@ typedef struct md_acme_driver_t {
     md_t *md;
     struct apr_array_header_t *domains;
     apr_array_header_t *ca_challenges;
+    const char *profile;
+    int profile_mandatory;
     
     int complete;
     apr_array_header_t *creds;       /* the new md_credentials_t */

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 21..52
21 struct md_result_t;
22 
23 typedef struct md_acme_driver_t {
24     md_proto_driver_t *driver;
25     void *sub_driver;
26     
27     int complete;
28 
29     md_pkey_t *privkey;              /* the new private key */
30     apr_array_header_t *certs;       /* the certifiacte chain, starting with the new one */
31     const char *next_up_link;        /* where the next chain cert is */
32     
33     md_acme_t *acme;
34     md_t *md;
35     struct apr_array_header_t *domains;
36     
37     apr_array_header_t *ca_challenges;
38     struct md_acme_order_t *order;
39     apr_interval_time_t authz_monitor_timeout;
40     
41     const char *csr_der_64;
42     apr_interval_time_t cert_poll_timeout;
43     
44 } md_acme_driver_t;
45 
46 apr_status_t md_acme_drive_set_acct(struct md_proto_driver_t *d, 
47                                     struct md_result_t *result);
48 apr_status_t md_acme_drive_setup_certificate(struct md_proto_driver_t *d, 
49                                              struct md_result_t *result);
50 apr_status_t md_acme_drive_cert_poll(struct md_proto_driver_t *d, int only_once);
51 
52 #endif /* md_acme_drive_h */
~~~

### modules/md/md_acme_order.c

~~~diff
--- a/modules/md/md_acme_order.c
+++ b/modules/md/md_acme_order.c
@@ -226,32 +226,33 @@ static apr_status_t p_purge(void *baton,
     md_store_t *store = baton;
     md_acme_order_t *order;
     md_store_group_t group;
-    const char *md_name, *setup_token;
+    const md_t *md;
+    const char *setup_token;
     apr_table_t *env;
     int i;
 
     group = (md_store_group_t)va_arg(ap, int);
-    md_name = va_arg(ap, const char *);
+    md = va_arg(ap, const md_t *);
     env = va_arg(ap, apr_table_t *);
 
-    if (APR_SUCCESS == md_acme_order_load(store, group, md_name, &order, p)) {
-        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "order loaded for %s", md_name);
+    if (APR_SUCCESS == md_acme_order_load(store, group, md->name, &order, p)) {
+        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "order loaded for %s", md->name);
         for (i = 0; i < order->challenge_setups->nelts; ++i) {
             setup_token = APR_ARRAY_IDX(order->challenge_setups, i, const char*);
             if (setup_token) {
                 md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
                               "order teardown setup %s", setup_token);
-                md_acme_authz_teardown(store, setup_token, md_name, env, p);
+                md_acme_authz_teardown(store, setup_token, md, env, p);
             }
         }
     }
-    return md_store_remove(store, group, md_name, MD_FN_ORDER, ptemp, 1);
+    return md_store_remove(store, group, md->name, MD_FN_ORDER, ptemp, 1);
 }
 
 apr_status_t md_acme_order_purge(md_store_t *store, apr_pool_t *p, md_store_group_t group,
-                                 const char *md_name, apr_table_t *env)
+                                 const md_t *md, apr_table_t *env)
 {
-    return md_util_pool_vdo(p_purge, store, p, group, md_name, env, NULL);
+    return md_util_pool_vdo(p_purge, store, p, group, md, env, NULL);
 }
 
 /**************************************************************************************************/
@@ -262,13 +263,16 @@ typedef struct {
     md_acme_order_t *order;
     md_acme_t *acme;
     const char *name;
+    const char *profile;
+    const char *ari_cert_id;
     apr_array_header_t *domains;
     md_result_t *result;
 } order_ctx_t;
 
-#define ORDER_CTX_INIT(ctx, p, o, a, n, d, r) \
+#define ORDER_CTX_INIT(ctx, p, o, a, n, d, pf, cid, r) \
     (ctx)->p = (p); (ctx)->order = (o); (ctx)->acme = (a); \
-    (ctx)->name = (n); (ctx)->domains = d; (ctx)->result = r
+    (ctx)->name = (n); (ctx)->domains = d; (ctx)->profile = pf; \
+    (ctx)->ari_cert_id = cid;(ctx)->result = r
 
 static apr_status_t identifier_to_json(void *value, md_json_t *json, apr_pool_t *p, void *baton)
 {
@@ -288,6 +292,10 @@ static apr_status_t on_init_order_regist
 
     jpayload = md_json_create(req->p);
     md_json_seta(ctx->domains, identifier_to_json, NULL, jpayload, "identifiers", NULL);
+    if (ctx->profile)
+        md_json_sets(ctx->profile, jpayload, "profile", NULL);
+    if (ctx->ari_cert_id)
+        md_json_sets(ctx->ari_cert_id, jpayload, "replaces", NULL);
 
     return md_acme_req_body_init(req, jpayload);
 } 
@@ -320,13 +328,14 @@ out:
 }
 
 apr_status_t md_acme_order_register(md_acme_order_t **porder, md_acme_t *acme, apr_pool_t *p, 
-                                    const char *name, apr_array_header_t *domains)
+                                    const char *name, apr_array_header_t *domains,
+                                    const char *profile, const char *ari_cert_id)
 {
     order_ctx_t ctx;
     apr_status_t rv;
     
     assert(MD_ACME_VERSION_MAJOR(acme->version) > 1);
-    ORDER_CTX_INIT(&ctx, p, NULL, acme, name, domains, NULL);
+    ORDER_CTX_INIT(&ctx, p, NULL, acme, name, domains, profile, ari_cert_id, NULL);
     rv = md_acme_POST(acme, acme->api.v2.new_order, on_init_order_register, on_order_upd, NULL, NULL, &ctx);
     *porder = (APR_SUCCESS == rv)? ctx.order : NULL;
     return rv;
@@ -339,8 +348,8 @@ apr_status_t md_acme_order_update(md_acm
     apr_status_t rv;
     
     assert(MD_ACME_VERSION_MAJOR(acme->version) > 1);
-    ORDER_CTX_INIT(&ctx, p, order, acme, NULL, NULL, result);
-    rv = md_acme_GET(acme, order->url, NULL, on_order_upd, NULL, NULL, &ctx);
+    ORDER_CTX_INIT(&ctx, p, order, acme, NULL, NULL, NULL, NULL, result);
+    rv = md_acme_GET(acme, order->url, NULL, on_order_upd, NULL, NULL, 1, &ctx);
     if (APR_SUCCESS != rv && APR_SUCCESS != acme->last->status) {
         md_result_dup(result, acme->last);
    
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 218..249
218                                     md_store_group_t group, const char *md_name, 
219                                     md_acme_order_t *authz_set, int create)
220 {
221     return md_util_pool_vdo(p_save, store, p, group, md_name, authz_set, create, NULL);
222 }
223 
224 static apr_status_t p_purge(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
225 {
226     md_store_t *store = baton;
227     md_acme_order_t *order;
228     md_store_group_t group;
229     const char *md_name, *setup_token;
230     apr_table_t *env;
231     int i;
232 
233     group = (md_store_group_t)va_arg(ap, int);
234     md_name = va_arg(ap, const char *);
235     env = va_arg(ap, apr_table_t *);
236 
237     if (APR_SUCCESS == md_acme_order_load(store, group, md_name, &order, p)) {
238         md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "order loaded for %s", md_name);
239         for (i = 0; i < order->challenge_setups->nelts; ++i) {
240             setup_token = APR_ARRAY_IDX(order->challenge_setups, i, const char*);
241             if (setup_token) {
242                 md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
243                               "order teardown setup %s", setup_token);
244                 md_acme_authz_teardown(store, setup_token, env, p);
245             }
246         }
247     }
248     return md_store_remove(store, group, md_name, MD_FN_ORDER, ptemp, 1);
249 }

Focal lines 254..285
254     return md_util_pool_vdo(p_purge, store, p, group, md_name, env, NULL);
255 }
256 
257 /**************************************************************************************************/
258 /* ACMEv2 order requests */
259 
260 typedef struct {
261     apr_pool_t *p;
262     md_acme_order_t *order;
263     md_acme_t *acme;
264     const char *name;
265     apr_array_header_t *domains;
266     md_result_t *result;
267 } order_ctx_t;
268 
269 #define ORDER_CTX_INIT(ctx, p, o, a, n, d, r) \
270     (ctx)->p = (p); (ctx)->order = (o); (ctx)->acme = (a); \
271     (ctx)->name = (n); (ctx)->domains = d; (ctx)->result = r
272 
273 static apr_status_t identifier_to_json(void *value, md_json_t *json, apr_pool_t *p, void *baton)
274 {
275     md_json_t *jid;
276     
277     (void)baton;
278     jid = md_json_create(p);
279     md_json_sets("dns", jid, "type", NULL);
280     md_json_sets(value, jid, "value", NULL);
281     return md_json_setj(jid, json, NULL);
282 }
283 
284 static apr_status_t on_init_order_register(md_acme_req_t *req, void *baton)
285 {

Focal lines 280..311
280     md_json_sets(value, jid, "value", NULL);
281     return md_json_setj(jid, json, NULL);
282 }
283 
284 static apr_status_t on_init_order_register(md_acme_req_t *req, void *baton)
285 {
286     order_ctx_t *ctx = baton;
287     md_json_t *jpayload;
288 
289     jpayload = md_json_create(req->p);
290     md_json_seta(ctx->domains, identifier_to_json, NULL, jpayload, "identifiers", NULL);
291 
292     return md_acme_req_body_init(req, jpayload);
293 } 
294 
295 static apr_status_t on_order_upd(md_acme_t *acme, apr_pool_t *p, const apr_table_t *hdrs, 
296                                  md_json_t *body, void *baton)
297 {
298     order_ctx_t *ctx = baton;
299     const char *location = apr_table_get(hdrs, "location");
300     apr_status_t rv = APR_SUCCESS;
301     
302     (void)acme;
303     (void)p;
304     if (!ctx->order) {
305         if (location) {
306             ctx->order = md_acme_order_create(ctx->p);
307             ctx->order->url = apr_pstrdup(ctx->p, location);
308             md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, ctx->p, "new order at %s", location);
309         }
310         else {
311             rv = APR_EINVAL;
~~~

### modules/md/md_acme_order.h

~~~diff
--- a/modules/md/md_acme_order.h
+++ b/modules/md/md_acme_order.h
@@ -60,7 +60,7 @@ apr_status_t md_acme_order_save(struct m
                                     md_acme_order_t *authz_set, int create);
 
 apr_status_t md_acme_order_purge(struct md_store_t *store, apr_pool_t *p, 
-                                 md_store_group_t group, const char *md_name,
+                                 md_store_group_t group, const md_t *md,
                                  apr_table_t *env);
 
 apr_status_t md_acme_order_start_challenges(md_acme_order_t *order, md_acme_t *acme,
@@ -76,7 +76,8 @@ apr_status_t md_acme_order_monitor_authz
 /* ACMEv2 only ************************************************************************************/
 
 apr_status_t md_acme_order_register(md_acme_order_t **porder, md_acme_t *acme, apr_pool_t *p, 
-                                    const char *name, struct apr_array_header_t *domains);
+                                    const char *name, struct apr_array_header_t *domains,
+                                    const char *profile, const char *ari_cert_id);
 
 apr_status_t md_acme_order_update(md_acme_order_t *order, md_acme_t *acme, 
                                   struct md_result_t *result, apr_pool_t *p);

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 52..83
52 struct md_json_t *md_acme_order_to_json(md_acme_order_t *set, apr_pool_t *p);
53 md_acme_order_t *md_acme_order_from_json(struct md_json_t *json, apr_pool_t *p);
54 
55 apr_status_t md_acme_order_load(struct md_store_t *store, md_store_group_t group, 
56                                     const char *md_name, md_acme_order_t **pauthz_set, 
57                                     apr_pool_t *p);
58 apr_status_t md_acme_order_save(struct md_store_t *store, apr_pool_t *p, 
59                                     md_store_group_t group, const char *md_name, 
60                                     md_acme_order_t *authz_set, int create);
61 
62 apr_status_t md_acme_order_purge(struct md_store_t *store, apr_pool_t *p, 
63                                  md_store_group_t group, const char *md_name,
64                                  apr_table_t *env);
65 
66 
67 apr_status_t md_acme_order_start_challenges(md_acme_order_t *order, md_acme_t *acme, 
68                                             apr_array_header_t *challenge_types,
69                                             md_store_t *store, const md_t *md, 
70                                             apr_table_t *env, struct md_result_t *result,
71                                             apr_pool_t *p);
72 
73 apr_status_t md_acme_order_monitor_authzs(md_acme_order_t *order, md_acme_t *acme, 
74                                           const md_t *md, apr_interval_time_t timeout,
75                                           struct md_result_t *result, apr_pool_t *p);
76 
77 /* ACMEv2 only ************************************************************************************/
78 
79 apr_status_t md_acme_order_register(md_acme_order_t **porder, md_acme_t *acme, apr_pool_t *p, 
80                                     const char *name, struct apr_array_header_t *domains);
81 
82 apr_status_t md_acme_order_update(md_acme_order_t *order, md_acme_t *acme, 
83                                   struct md_result_t *result, apr_pool_t *p);

Focal lines 68..92
68                                             apr_array_header_t *challenge_types,
69                                             md_store_t *store, const md_t *md, 
70                                             apr_table_t *env, struct md_result_t *result,
71                                             apr_pool_t *p);
72 
73 apr_status_t md_acme_order_monitor_authzs(md_acme_order_t *order, md_acme_t *acme, 
74                                           const md_t *md, apr_interval_time_t timeout,
75                                           struct md_result_t *result, apr_pool_t *p);
76 
77 /* ACMEv2 only ************************************************************************************/
78 
79 apr_status_t md_acme_order_register(md_acme_order_t **porder, md_acme_t *acme, apr_pool_t *p, 
80                                     const char *name, struct apr_array_header_t *domains);
81 
82 apr_status_t md_acme_order_update(md_acme_order_t *order, md_acme_t *acme, 
83                                   struct md_result_t *result, apr_pool_t *p);
84 
85 apr_status_t md_acme_order_await_ready(md_acme_order_t *order, md_acme_t *acme, 
86                                        const md_t *md, apr_interval_time_t timeout, 
87                                        struct md_result_t *result, apr_pool_t *p);
88 apr_status_t md_acme_order_await_valid(md_acme_order_t *order, md_acme_t *acme, 
89                                        const md_t *md, apr_interval_time_t timeout, 
90                                        struct md_result_t *result, apr_pool_t *p);
91 
92 #endif /* md_acme_order_h */
~~~

### modules/md/md_acmev2_drive.c

~~~diff
--- a/modules/md/md_acmev2_drive.c
+++ b/modules/md/md_acmev2_drive.c
@@ -56,7 +56,9 @@ static apr_status_t ad_setup_order(md_pr
     md_acme_driver_t *ad = d->baton;
     apr_status_t rv;
     md_t *md = ad->md;
-    
+    const char *profile = NULL;
+    const char *ari_cert_id = NULL;
+
     assert(ad->md);
     assert(ad->acme);
 
@@ -73,11 +75,63 @@ static apr_status_t ad_setup_order(md_pr
     }
     else if (!APR_STATUS_IS_ENOENT(rv)) {
         md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: loading order", md->name);
-        md_acme_order_purge(d->store, d->p, MD_SG_STAGING, md->name, d->env);
+        md_acme_order_purge(d->store, d->p, MD_SG_STAGING, md, d->env);
     }
     
-    md_result_activity_setn(result, "Creating new order");
-    rv = md_acme_order_register(&ad->order, ad->acme, d->p, d->md->name, ad->domains);
+    if (ad->cred->spec && ad->md->ca_account) {
+        /* are we replacing a previous certificate on the same account? */
+        int i;
+        for (i = 0; i < md_pkeys_spec_count(d->md->pks); ++i) {
+            md_pkey_spec_t *spec = md_pkeys_spec_get(d->md->pks, i);
+            const md_pubcert_t *pubcert;
+            const md_cert_t *cert;
+            if (md_pkey_spec_eq(ad->cred->spec, spec)) {
+                rv = md_reg_get_pubcert(&pubcert, d->reg, d->md, i, d->p);
+                if (rv == APR_SUCCESS) {
+                    cert = APR_ARRAY_IDX(pubcert->certs, 0, const md_cert_t*);
+                    if (cert) {
+                        md_cert_get_ari_cert_id(&ari_cert_id, cert, d->p);
+                        break;
+                    }
+                }
+            }
+        }
+    }
+
+    md_result_activity_printf(result, "Creating new order, key-spec=%s, "
+                              "profile=%s, replacing-cert=%s",
+                              ad->cred->spec? md_pkey_spec_to_str(ad->cred->spec, d->p) : "default",
+                              ad->profile? ad->profile : "none",
+                              ari_cert_id? ari_cert_id : "none");
+
+    if (ad->profile) {
+        if (ad->acme->api.v2.profiles) {
+            int i;
+            for (i = 0; !profile && i < ad->acme->api.v2.profiles->nelts; ++i) {
+                const char *s = APR_ARRAY_IDX(ad->acme->api.v2.profiles, i, const char*);
+                if (!apr_cstr_casecmp(s, ad->profile))
+                   profile = s;
+            }
+        }
+        if (profile)
+            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p,
+                          "%s: ordering ACME profile '%s'", md->name, profile);
+        else if (ad->profile_mandatory) {
+            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, d->p,
+                          "%s: mandatory ACME profile '%s' is not offered by CA",
+                          md->name, ad->profile);
+            rv = APR_EINVAL;
+            goto leave;
+        }
+        else {
+            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p,
+                          "%s: ACME profile '%s' is not offered by CA, continuing without",
+                          md->name, ad->profile);
+        }
+    }
+
+    rv = md_acme_order_register(&ad->order, ad->acme, d->p, d->md->name,
+                                ad->domains, profile, ari_cert_id);
     if (APR_SUCCESS !=rv) goto leave;
     rv = md_acme_order_save(d->store, d->p, MD_SG_STAGING, d->md->name, ad->order, 0);
     if (APR_SUCCESS != rv) {
@@ -128,7 +182,7 @@ apr_status_t md_acmev2_drive_renew(md_ac
         || MD_ACME_ORDER_ST_INVALID == ad->order->status) {
         /* order is invalid or no longer known at the ACME server */
         ad->order = NULL;
-        md_acme_order_purge(d->store, d->p, MD_SG_STAGING, d->md->name, d->env);
+        md_acme_order_purge(d->store, d->p, MD_SG_STAGING, d->md, d->env);
     }
     else if (APR_SUCCESS != rv) {
         goto leave;
@@ -145,18 +199,24 @@ retry:
     if (!is_new_order && APR_STATUS_IS_EINVAL(rv)) {
         /* found 'invalid' domains in previous order, need to start over */
         ad->order = NULL;
-        md_acme_order_purge(d->store, d->p, MD_SG_STAGING, d->md->name, d->env);
+        md_acme_order_purge(d->store, d->p, MD_SG_STAGING, d->md, d->env);
         goto retry;
     }
     if (APR_SUCCESS != rv) goto leave;
     
     rv = md_acme_order_monitor_authzs(ad->order, ad->acme, d->md,
                                       ad->authz_monitor_timeout, result, d->p);
-    if (APR_SUCCESS != rv) goto leave;
+    i
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 48..79
48 /* order setup */
49 
50 /**
51  * Either we have an order stored in the STAGING area, or we need to create a 
52  * new one at the ACME server.
53  */
54 static apr_status_t ad_setup_order(md_proto_driver_t *d, md_result_t *result)
55 {
56     md_acme_driver_t *ad = d->baton;
57     apr_status_t rv;
58     md_t *md = ad->md;
59     
60     assert(ad->md);
61     assert(ad->acme);
62 
63     /* For each domain in MD: AUTHZ setup
64      * if an AUTHZ resource is known, check if it is still valid
65      * if known AUTHZ resource is not valid, remove, goto 4.1.1
66      * if no AUTHZ available, create a new one for the domain, store it
67      */
68     rv = md_acme_order_load(d->store, MD_SG_STAGING, md->name, &ad->order, d->p);
69     if (APR_SUCCESS == rv) {
70         md_result_activity_setn(result, "Loaded order from staging");
71         goto leave;
72     }
73     else if (!APR_STATUS_IS_ENOENT(rv)) {
74         md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: loading order", md->name);
75         md_acme_order_purge(d->store, d->p, MD_SG_STAGING, md->name, d->env);
76     }
77     
78     md_result_activity_setn(result, "Creating new order");
79     rv = md_acme_order_register(&ad->order, ad->acme, d->p, d->md->name, ad->domains);

Focal lines 65..96
65      * if known AUTHZ resource is not valid, remove, goto 4.1.1
66      * if no AUTHZ available, create a new one for the domain, store it
67      */
68     rv = md_acme_order_load(d->store, MD_SG_STAGING, md->name, &ad->order, d->p);
69     if (APR_SUCCESS == rv) {
70         md_result_activity_setn(result, "Loaded order from staging");
71         goto leave;
72     }
73     else if (!APR_STATUS_IS_ENOENT(rv)) {
74         md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: loading order", md->name);
75         md_acme_order_purge(d->store, d->p, MD_SG_STAGING, md->name, d->env);
76     }
77     
78     md_result_activity_setn(result, "Creating new order");
79     rv = md_acme_order_register(&ad->order, ad->acme, d->p, d->md->name, ad->domains);
80     if (APR_SUCCESS !=rv) goto leave;
81     rv = md_acme_order_save(d->store, d->p, MD_SG_STAGING, d->md->name, ad->order, 0);
82     if (APR_SUCCESS != rv) {
83         md_result_set(result, rv, "saving order in staging");
84     }
85     
86 leave:
87     md_acme_report_result(ad->acme, rv, result);
88     return rv;
89 }
90 
91 /**************************************************************************************************/
92 /* ACMEv2 renewal */
93 
94 apr_status_t md_acmev2_drive_renew(md_acme_driver_t *ad, md_proto_driver_t *d, md_result_t *result)
95 {
96     apr_status_t rv = APR_SUCCESS;

Focal lines 120..151
120     }
121     
122     rv = md_acme_order_update(ad->order, ad->acme, result, d->p);
123     if (APR_STATUS_IS_ENOENT(rv)) {
124         /* order is no longer known at the ACME server */
125         ad->order = NULL;
126         md_acme_order_purge(d->store, d->p, MD_SG_STAGING, d->md->name, d->env);
127     }
128     else if (APR_SUCCESS != rv) {
129         goto leave;
130     }
131     
132     if (!ad->order) {
133         rv = ad_setup_order(d, result);
134         if (APR_SUCCESS != rv) goto leave;
135     }
136     
137     rv = md_acme_order_start_challenges(ad->order, ad->acme, ad->ca_challenges,
138                                         d->store, d->md, d->env, result, d->p);
139     if (APR_SUCCESS != rv) goto leave;
140     
141     rv = md_acme_order_monitor_authzs(ad->order, ad->acme, d->md,
142                                       ad->authz_monitor_timeout, result, d->p);
143     if (APR_SUCCESS != rv) goto leave;
144     
145     rv = md_acme_order_await_ready(ad->order, ad->acme, d->md, 
146                                    ad->authz_monitor_timeout, result, d->p);
147     if (APR_SUCCESS != rv) goto leave;
148     
149     rv = md_acme_drive_setup_certificate(d, result);
150     if (APR_SUCCESS != rv) goto leave;
151     
~~~

### modules/md/md_core.c

~~~diff
--- a/modules/md/md_core.c
+++ b/modules/md/md_core.c
@@ -112,6 +112,8 @@ md_t *md_create_empty(apr_pool_t *p)
         md->transitive = -1;
         md->acme_tls_1_domains = apr_array_make(p, 5, sizeof(const char *));
         md->stapling = -1;
+        md->profile_mandatory = -1;
+        md->ari_renewals = -1;
         md->defn_name = "unknown";
         md->defn_line_number = 0;
     }
@@ -241,8 +243,11 @@ md_t *md_clone(apr_pool_t *p, const md_t
         md->renew_window = src->renew_window;
         md->warn_window = src->warn_window;
         md->contacts = md_array_str_clone(p, src->contacts);
-        if (src->ca_url) md->ca_url = apr_pstrdup(p, src->ca_url);
         if (src->ca_proto) md->ca_proto = apr_pstrdup(p, src->ca_proto);
+        if (src->ca_urls) {
+            md->ca_urls = md_array_str_clone(p, src->ca_urls);
+        }
+        if (src->ca_effective) md->ca_effective = apr_pstrdup(p, src->ca_effective);
         if (src->ca_account) md->ca_account = apr_pstrdup(p, src->ca_account);
         if (src->ca_agreement) md->ca_agreement = apr_pstrdup(p, src->ca_agreement);
         if (src->defn_name) md->defn_name = apr_pstrdup(p, src->defn_name);
@@ -252,6 +257,7 @@ md_t *md_clone(apr_pool_t *p, const md_t
         }
         md->acme_tls_1_domains = md_array_str_compact(p, src->acme_tls_1_domains, 0);
         md->stapling = src->stapling;
+        if (src->dns01_cmd) md->dns01_cmd = apr_pstrdup(p, src->dns01_cmd);
         if (src->cert_files) md->cert_files = md_array_str_clone(p, src->cert_files);
         if (src->pkey_files) md->pkey_files = md_array_str_clone(p, src->pkey_files);
     }    
@@ -272,7 +278,10 @@ md_json_t *md_to_json(const md_t *md, ap
         md_json_setl(md->transitive, json, MD_KEY_TRANSITIVE, NULL);
         md_json_sets(md->ca_account, json, MD_KEY_CA, MD_KEY_ACCOUNT, NULL);
         md_json_sets(md->ca_proto, json, MD_KEY_CA, MD_KEY_PROTO, NULL);
-        md_json_sets(md->ca_url, json, MD_KEY_CA, MD_KEY_URL, NULL);
+        md_json_sets(md->ca_effective, json, MD_KEY_CA, MD_KEY_URL, NULL);
+        if (md->ca_urls && !apr_is_empty_array(md->ca_urls)) {
+            md_json_setsa(md->ca_urls, json, MD_KEY_CA, MD_KEY_URLS, NULL);
+        }
         md_json_sets(md->ca_agreement, json, MD_KEY_CA, MD_KEY_AGREEMENT, NULL);
         if (!md_pkeys_spec_is_empty(md->pks)) {
             md_json_setj(md_pkeys_spec_to_json(md->pks, p), json, MD_KEY_PKEY, NULL);
@@ -305,10 +314,14 @@ md_json_t *md_to_json(const md_t *md, ap
         if (md->cert_files) md_json_setsa(md->cert_files, json, MD_KEY_CERT_FILES, NULL);
         if (md->pkey_files) md_json_setsa(md->pkey_files, json, MD_KEY_PKEY_FILES, NULL);
         md_json_setb(md->stapling > 0, json, MD_KEY_STAPLING, NULL);
+        if (md->dns01_cmd) md_json_sets(md->dns01_cmd, json, MD_KEY_CMD_DNS01, NULL);
         if (md->ca_eab_kid && strcmp("none", md->ca_eab_kid)) {
             md_json_sets(md->ca_eab_kid, json, MD_KEY_EAB, MD_KEY_KID, NULL);
             if (md->ca_eab_hmac) md_json_sets(md->ca_eab_hmac, json, MD_KEY_EAB, MD_KEY_HMAC, NULL);
         }
+        if (md->profile) md_json_sets(md->profile, json, MD_KEY_PROFILE, NULL);
+        md_json_setb(md->profile_mandatory > 0, json, MD_KEY_PROFILE_MANDATORY, NULL);
+        md_json_setb(md->ari_renewals > 0, json, MD_KEY_ARI_RENEWALS, NULL);
         return json;
     }
     return NULL;
@@ -324,7 +337,16 @@ md_t *md_from_json(md_json_t *json, apr_
         md_json_dupsa(md->contacts, p, json, MD_KEY_CONTACTS, NULL);
         md->ca_account = md_json_dups(p, json, MD_KEY_CA, MD_KEY_ACCOUNT, NULL);
         md->ca_proto = md_json_dups(p, json, MD_KEY_CA, MD_KEY_PROTO, NULL);
-        md->ca_url = md_json_dups(p, json, MD_KEY_CA, MD_KEY_URL, NULL);
+        md->ca_effective = md_json_dups(p, json, MD_KEY_CA, MD_KEY_URL, NULL);
+        if (md_json_has_key(json, MD_KEY_CA, MD_KEY_URLS, NULL)) {
+            md->ca_urls = apr_array_make(p, 5, sizeof(const char*));
+            md_json_dupsa(md->ca_urls, p, json, MD_KEY_CA, MD_KEY_URLS, NULL);
+        }
+        else if (md->ca_effective) {
+            /* compat for old format where we had only a single url */
+            md->ca_urls = apr_array_make(p, 5, sizeof(const char*));
+            APR_ARRAY_PUSH(md->ca_urls, const char*) = md->ca_effective;
+        }
         md->ca_agreement = md_json_dups(p, json, MD_KEY_CA, MD_KEY_AGREEMENT, NULL);
         if (md_json_has_key(json, MD_KEY_PKEY, NULL)) {
             md->pk
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 104..135
104         md->contacts = apr_array_make(p, 5, sizeof(const char *));
105         md->renew_mode = MD_RENEW_DEFAULT;
106         md->require_https = MD_REQUIRE_UNSET;
107         md->must_staple = -1;
108         md->transitive = -1;
109         md->acme_tls_1_domains = apr_array_make(p, 5, sizeof(const char *));
110         md->defn_name = "unknown";
111         md->defn_line_number = 0;
112     }
113     return md;
114 }
115 
116 int md_equal_domains(const md_t *md1, const md_t *md2, int case_sensitive)
117 {
118     int i;
119     if (md1->domains->nelts == md2->domains->nelts) {
120         for (i = 0; i < md1->domains->nelts; ++i) {
121             const char *name1 = APR_ARRAY_IDX(md1->domains, i, const char*);
122             if (!md_contains(md2, name1, case_sensitive)) {
123                 return 0;
124             }
125         }
126         return 1;
127     }
128     return 0;
129 }
130 
131 int md_contains_domains(const md_t *md1, const md_t *md2)
132 {
133     int i;
134     if (md1->domains->nelts >= md2->domains->nelts) {
135         for (i = 0; i < md2->domains->nelts; ++i) {

Focal lines 233..264
233     if (md) {
234         memcpy(md, src, sizeof(*md));
235         md->domains = apr_array_copy(p, src->domains);
236         md->contacts = apr_array_copy(p, src->contacts);
237         if (src->ca_challenges) {
238             md->ca_challenges = apr_array_copy(p, src->ca_challenges);
239         }
240         md->acme_tls_1_domains = apr_array_copy(p, src->acme_tls_1_domains);
241     }    
242     return md;   
243 }
244 
245 md_t *md_clone(apr_pool_t *p, const md_t *src)
246 {
247     md_t *md;
248     
249     md = apr_pcalloc(p, sizeof(*md));
250     if (md) {
251         md->state = src->state;
252         md->name = apr_pstrdup(p, src->name);
253         md->require_https = src->require_https;
254         md->must_staple = src->must_staple;
255         md->renew_mode = src->renew_mode;
256         md->domains = md_array_str_compact(p, src->domains, 0);
257         md->pkey_spec = src->pkey_spec;
258         md->renew_window = src->renew_window;
259         md->warn_window = src->warn_window;
260         md->contacts = md_array_str_clone(p, src->contacts);
261         if (src->ca_url) md->ca_url = apr_pstrdup(p, src->ca_url);
262         if (src->ca_proto) md->ca_proto = apr_pstrdup(p, src->ca_proto);
263         if (src->ca_account) md->ca_account = apr_pstrdup(p, src->ca_account);
264         if (src->ca_agreement) md->ca_agreement = apr_pstrdup(p, src->ca_agreement);

Focal lines 244..275
244 
245 md_t *md_clone(apr_pool_t *p, const md_t *src)
246 {
247     md_t *md;
248     
249     md = apr_pcalloc(p, sizeof(*md));
250     if (md) {
251         md->state = src->state;
252         md->name = apr_pstrdup(p, src->name);
253         md->require_https = src->require_https;
254         md->must_staple = src->must_staple;
255         md->renew_mode = src->renew_mode;
256         md->domains = md_array_str_compact(p, src->domains, 0);
257         md->pkey_spec = src->pkey_spec;
258         md->renew_window = src->renew_window;
259         md->warn_window = src->warn_window;
260         md->contacts = md_array_str_clone(p, src->contacts);
261         if (src->ca_url) md->ca_url = apr_pstrdup(p, src->ca_url);
262         if (src->ca_proto) md->ca_proto = apr_pstrdup(p, src->ca_proto);
263         if (src->ca_account) md->ca_account = apr_pstrdup(p, src->ca_account);
264         if (src->ca_agreement) md->ca_agreement = apr_pstrdup(p, src->ca_agreement);
265         if (src->defn_name) md->defn_name = apr_pstrdup(p, src->defn_name);
266         md->defn_line_number = src->defn_line_number;
267         if (src->ca_challenges) {
268             md->ca_challenges = md_array_str_clone(p, src->ca_challenges);
269         }
270         md->acme_tls_1_domains = md_array_str_compact(p, src->acme_tls_1_domains, 0);
271         if (src->cert_file) md->cert_file = apr_pstrdup(p, src->cert_file);
272         if (src->pkey_file) md->pkey_file = apr_pstrdup(p, src->pkey_file);
273     }    
274     return md;   
275 }
~~~

### modules/md/md_crypt.c

~~~diff
--- a/modules/md/md_crypt.c
+++ b/modules/md/md_crypt.c
@@ -32,6 +32,9 @@
 #include <openssl/rand.h>
 #include <openssl/rsa.h>
 #include <openssl/x509v3.h>
+#if OPENSSL_VERSION_NUMBER >= 0x30000000L
+#include <openssl/core_names.h>
+#endif
 
 #include "md.h"
 #include "md_crypt.h"
@@ -54,22 +57,20 @@
 #include <process.h>
 #endif
 
-#if defined(LIBRESSL_VERSION_NUMBER)
-/* Missing from LibreSSL */
-#define MD_USE_OPENSSL_PRE_1_1_API (LIBRESSL_VERSION_NUMBER < 0x2070000f)
-#else /* defined(LIBRESSL_VERSION_NUMBER) */
-#define MD_USE_OPENSSL_PRE_1_1_API (OPENSSL_VERSION_NUMBER < 0x10100000L)
-#endif
-
-#if defined(LIBRESSL_VERSION_NUMBER) || (OPENSSL_VERSION_NUMBER < 0x10100000L) 
-/* Missing from LibreSSL and only available since OpenSSL v1.1.x */
-#ifndef OPENSSL_NO_CT
-#define OPENSSL_NO_CT
+#if !defined(OPENSSL_NO_CT) \
+    && OPENSSL_VERSION_NUMBER >= 0x10100000L \
+    && (!defined(LIBRESSL_VERSION_NUMBER) \
+        || LIBRESSL_VERSION_NUMBER >= 0x3050000fL)
+/* Missing from LibreSSL < 3.5.0 and only available since OpenSSL v1.1.x */
+#include <openssl/ct.h>
+#define MD_HAVE_CT 1
 #endif
+#ifndef MD_HAVE_CT
+#define MD_HAVE_CT 0
 #endif
 
-#ifndef OPENSSL_NO_CT
-#include <openssl/ct.h>
+#if OPENSSL_VERSION_NUMBER < 0x10100000L
+#define MD_OPENSSL_10x
 #endif
 
 static int initialized;
@@ -205,12 +206,13 @@ static int pem_passwd(char *buf, int siz
 
 /* Get the apr time (micro seconds, since 1970) from an ASN1 time, as stored in X509
  * certificates. OpenSSL now has a utility function, but other *SSL derivatives have
- * not caughts up yet or chose to ignore. An alternative is implemented, we prefer 
+ * not caught up yet or chose to ignore. An alternative is implemented, we prefer
  * however the *SSL to maintain such things.
  */
 static apr_time_t md_asn1_time_get(const ASN1_TIME* time)
 {
-#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)
+#if OPENSSL_VERSION_NUMBER < 0x10002000L || (defined(LIBRESSL_VERSION_NUMBER) && \
+                                             LIBRESSL_VERSION_NUMBER < 0x3060000fL)
     /* courtesy: https://stackoverflow.com/questions/10975542/asn1-time-to-time-t-conversion#11263731
      * all bugs are mine */
     apr_time_exp_t t;
@@ -218,6 +220,10 @@ static apr_time_t md_asn1_time_get(const
     const char* str = (const char*) time->data;
     apr_size_t i = 0;
 
+    if ((time->length < 12) || (
+        (time->type == V_ASN1_GENERALIZEDTIME) && time->length < 16))
+      return 0;
+
     memset(&t, 0, sizeof(t));
 
     if (time->type == V_ASN1_UTCTIME) {/* two digit year */
@@ -259,9 +265,9 @@ static apr_time_t md_asn1_time_get(const
 #endif
 }
 
-apr_time_t md_asn1_generalized_time_get(void *ASN1_GENERALIZEDTIME)
+apr_time_t md_asn1_generalized_time_get(void *asn1_gtime)
 {
-    return md_asn1_time_get(ASN1_GENERALIZEDTIME);
+    return md_asn1_time_get(asn1_gtime);
 }
 
 /**************************************************************************************************/
@@ -336,7 +342,7 @@ int md_pkeys_spec_contains_ec(md_pkeys_s
     for (i = 0; i < pks->specs->nelts; ++i) {
         spec = APR_ARRAY_IDX(pks->specs, i, md_pkey_spec_t*);
         if (MD_PKEY_TYPE_EC == spec->type 
-            && !apr_strnatcasecmp(curve, spec->params.ec.curve)) return 1;   
+            && !apr_cstr_casecmp(curve, spec->params.ec.curve)) return 1;   
     }
     return 0;
 }
@@ -351,6 +357,24 @@ void md_pkeys_spec_add_ec(md_pkeys_spec_
     md_pkeys_spec_add(pks, spec);
 }
 
+const char *md_pkey_spec_to_str(const md_pkey_spec_t *spec, apr_pool_t *p)
+{
+    switch (spec->type) {
+        case MD_PKEY_TYPE_DEFAULT:
+            return "default";
+        case MD_PKEY_TYPE_RSA:
+            if (spec->params.rsa.bits >= MD_PKEY_RSA_BITS_MIN)
+                return apr_psprintf(p, "rsa-%d", spec->params.rsa.bits);
+            return "rsa";
+        case MD_PKEY_TYPE_EC:
+            if (spec->params.ec.curve)
+                return apr_psprintf(p, "ec-%s", spec->params.ec.curve);
+            return "ec";
+        default:
+            return "unsupported";
+    }
+}
+
 md_json_t *md_pkey_spec_to_json(const md_pkey_spec_t *spec, apr_pool_t *p)
 {
     md_json_t *json = md_json_create(p);
@@ -408,10 +432,10 @@ md_pkey_spec_t *md_pkey_spec_from_json(s
     
     if (spec) {
         s = md_json_gets(json, MD_KEY_TYPE, NULL);
-        if (!s || !apr_strnatcasecmp("Default", s)) {
+        if (!s || !apr_cstr_casecmp("Default", s)) {
             spec->type = MD_PKEY_TY
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 24..55
24 #include <apr_strings.h>
25 
26 #include <openssl/err.h>
27 #include <openssl/evp.h>
28 #include <openssl/pem.h>
29 #include <openssl/rand.h>
30 #include <openssl/rsa.h>
31 #include <openssl/x509v3.h>
32 
33 #include "md.h"
34 #include "md_crypt.h"
35 #include "md_json.h"
36 #include "md_log.h"
37 #include "md_http.h"
38 #include "md_util.h"
39 
40 /* getpid for *NIX */
41 #if APR_HAVE_SYS_TYPES_H
42 #include <sys/types.h>
43 #endif
44 #if APR_HAVE_UNISTD_H
45 #include <unistd.h>
46 #endif
47 
48 /* getpid for Windows */
49 #if APR_HAVE_PROCESS_H
50 #include <process.h>
51 #endif
52 
53 #if defined(LIBRESSL_VERSION_NUMBER)
54 /* Missing from LibreSSL */
55 #define MD_USE_OPENSSL_PRE_1_1_API (LIBRESSL_VERSION_NUMBER < 0x2070000f)

Focal lines 46..77
46 #endif
47 
48 /* getpid for Windows */
49 #if APR_HAVE_PROCESS_H
50 #include <process.h>
51 #endif
52 
53 #if defined(LIBRESSL_VERSION_NUMBER)
54 /* Missing from LibreSSL */
55 #define MD_USE_OPENSSL_PRE_1_1_API (LIBRESSL_VERSION_NUMBER < 0x2070000f)
56 #else /* defined(LIBRESSL_VERSION_NUMBER) */
57 #define MD_USE_OPENSSL_PRE_1_1_API (OPENSSL_VERSION_NUMBER < 0x10100000L)
58 #endif
59 
60 #if defined(LIBRESSL_VERSION_NUMBER) || (OPENSSL_VERSION_NUMBER < 0x10100000L) 
61 /* Missing from LibreSSL and only available since OpenSSL v1.1.x */
62 #ifndef OPENSSL_NO_CT
63 #define OPENSSL_NO_CT
64 #endif
65 #endif
66 
67 #ifndef OPENSSL_NO_CT
68 #include <openssl/ct.h>
69 #endif
70 
71 static int initialized;
72 
73 struct md_pkey_t {
74     apr_pool_t *pool;
75     EVP_PKEY   *pkey;
76 };
77 

Focal lines 197..228
197 /**************************************************************************************************/
198 /* date time things */
199 
200 /* Get the apr time (micro seconds, since 1970) from an ASN1 time, as stored in X509
201  * certificates. OpenSSL now has a utility function, but other *SSL derivatives have
202  * not caughts up yet or chose to ignore. An alternative is implemented, we prefer 
203  * however the *SSL to maintain such things.
204  */
205 static apr_time_t md_asn1_time_get(const ASN1_TIME* time)
206 {
207 #if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)
208     /* courtesy: https://stackoverflow.com/questions/10975542/asn1-time-to-time-t-conversion#11263731
209      * all bugs are mine */
210     apr_time_exp_t t;
211     apr_time_t ts;
212     const char* str = (const char*) time->data;
213     apr_size_t i = 0;
214 
215     memset(&t, 0, sizeof(t));
216 
217     if (time->type == V_ASN1_UTCTIME) {/* two digit year */
218         t.tm_year = (str[i++] - '0') * 10;
219         t.tm_year += (str[i++] - '0');
220         if (t.tm_year < 70)
221             t.tm_year += 100;
222     } 
223     else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
224         t.tm_year = (str[i++] - '0') * 1000;
225         t.tm_year+= (str[i++] - '0') * 100;
226         t.tm_year+= (str[i++] - '0') * 10;
227         t.tm_year+= (str[i++] - '0');
228         t.tm_year -= 1900;
~~~

### modules/md/md_crypt.h

~~~diff
--- a/modules/md/md_crypt.h
+++ b/modules/md/md_crypt.h
@@ -68,6 +68,8 @@ typedef struct md_pkey_spec_t {
     } params;
 } md_pkey_spec_t;
 
+int md_pkey_spec_eq(const md_pkey_spec_t *s1, const md_pkey_spec_t *s2);
+
 typedef struct md_pkeys_spec_t {
     apr_pool_t *p;
     struct apr_array_header_t *specs;
@@ -90,6 +92,8 @@ md_pkey_spec_t *md_pkeys_spec_get(const
 int md_pkeys_spec_count(const md_pkeys_spec_t *pks);
 void md_pkeys_spec_add(md_pkeys_spec_t *pks, md_pkey_spec_t *spec);
 
+const char *md_pkey_spec_to_str(const md_pkey_spec_t *spec, apr_pool_t *p);
+
 struct md_json_t *md_pkey_spec_to_json(const md_pkey_spec_t *spec, apr_pool_t *p);
 md_pkey_spec_t *md_pkey_spec_from_json(struct md_json_t *json, apr_pool_t *p);
 struct md_json_t *md_pkeys_spec_to_json(const md_pkeys_spec_t *pks, apr_pool_t *p);
@@ -117,6 +121,12 @@ void *md_pkey_get_EVP_PKEY(struct md_pke
 apr_status_t md_crypt_hmac64(const char **pmac64, const struct md_data_t *hmac_key,
                              apr_pool_t *p, const char *d, size_t dlen);
 
+/**
+ * Read a private key from a http response.
+ */
+apr_status_t md_pkey_read_http(md_pkey_t **ppkey, apr_pool_t *pool,
+                               const struct md_http_response_t *res);
+
 /**************************************************************************************************/
 /* X509 certificates */
 
@@ -179,6 +189,12 @@ apr_time_t md_cert_get_not_after(const m
 apr_time_t md_cert_get_not_before(const md_cert_t *cert);
 struct md_timeperiod_t md_cert_get_valid(const md_cert_t *cert);
 
+/**
+ * Return != 0 iff the hash values of the certificates are equal.
+ */
+int md_certs_are_equal(const md_cert_t *a, const md_cert_t *b);
+
+const char *md_cert_get_issuer_name(const md_cert_t *cert, apr_pool_t *p);
 apr_status_t md_cert_get_issuers_uri(const char **puri, const md_cert_t *cert, apr_pool_t *p);
 apr_status_t md_cert_get_alt_names(apr_array_header_t **pnames, const md_cert_t *cert, apr_pool_t *p);
 
@@ -223,6 +239,9 @@ apr_status_t md_cert_get_ocsp_responder_
 
 apr_status_t md_check_cert_and_pkey(struct apr_array_header_t *certs, md_pkey_t *pkey);
 
+apr_status_t md_cert_get_ari_cert_id(const char **pari_cert_id,
+                                     const md_cert_t *cert, apr_pool_t *p);
+
 
 /**************************************************************************************************/
 /* X509 certificate transparency */

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 60..91
60     union {
61         md_pkey_rsa_spec_t rsa;
62     } params;
63 } md_pkey_spec_t;
64 
65 apr_status_t md_crypt_init(apr_pool_t *pool);
66 
67 apr_status_t md_pkey_gen(md_pkey_t **ppkey, apr_pool_t *p, md_pkey_spec_t *spec);
68 void md_pkey_free(md_pkey_t *pkey);
69 
70 const char *md_pkey_get_rsa_e64(md_pkey_t *pkey, apr_pool_t *p);
71 const char *md_pkey_get_rsa_n64(md_pkey_t *pkey, apr_pool_t *p);
72 
73 apr_status_t md_pkey_fload(md_pkey_t **ppkey, apr_pool_t *p, 
74                            const char *pass_phrase, apr_size_t pass_len,
75                            const char *fname);
76 apr_status_t md_pkey_fsave(md_pkey_t *pkey, apr_pool_t *p, 
77                            const char *pass_phrase, apr_size_t pass_len, 
78                            const char *fname, apr_fileperms_t perms);
79 
80 apr_status_t md_crypt_sign64(const char **psign64, md_pkey_t *pkey, apr_pool_t *p, 
81                              const char *d, size_t dlen);
82 
83 void *md_pkey_get_EVP_PKEY(struct md_pkey_t *pkey);
84 
85 struct md_json_t *md_pkey_spec_to_json(const md_pkey_spec_t *spec, apr_pool_t *p);
86 md_pkey_spec_t *md_pkey_spec_from_json(struct md_json_t *json, apr_pool_t *p);
87 int md_pkey_spec_eq(md_pkey_spec_t *spec1, md_pkey_spec_t *spec2);
88 
89 /**************************************************************************************************/
90 /* X509 certificates */
91 

Focal lines 82..113
82 
83 void *md_pkey_get_EVP_PKEY(struct md_pkey_t *pkey);
84 
85 struct md_json_t *md_pkey_spec_to_json(const md_pkey_spec_t *spec, apr_pool_t *p);
86 md_pkey_spec_t *md_pkey_spec_from_json(struct md_json_t *json, apr_pool_t *p);
87 int md_pkey_spec_eq(md_pkey_spec_t *spec1, md_pkey_spec_t *spec2);
88 
89 /**************************************************************************************************/
90 /* X509 certificates */
91 
92 typedef struct md_cert_t md_cert_t;
93 
94 typedef enum {
95     MD_CERT_UNKNOWN,
96     MD_CERT_VALID,
97     MD_CERT_EXPIRED
98 } md_cert_state_t;
99 
100 void md_cert_free(md_cert_t *cert);
101 void *md_cert_get_X509(const md_cert_t *cert);
102 
103 apr_status_t md_cert_fload(md_cert_t **pcert, apr_pool_t *p, const char *fname);
104 apr_status_t md_cert_fsave(md_cert_t *cert, apr_pool_t *p, 
105                            const char *fname, apr_fileperms_t perms);
106 
107 /**
108  * Read a x509 certificate from a http response.
109  * Will return APR_ENOENT if content-type is not recognized (currently
110  * only "application/pkix-cert" is supported).
111  */
112 apr_status_t md_cert_read_http(md_cert_t **pcert, apr_pool_t *pool, 
113                                const struct md_http_response_t *res);

Focal lines 109..140
109  * Will return APR_ENOENT if content-type is not recognized (currently
110  * only "application/pkix-cert" is supported).
111  */
112 apr_status_t md_cert_read_http(md_cert_t **pcert, apr_pool_t *pool, 
113                                const struct md_http_response_t *res);
114 
115 /**
116  * Read one or even a chain of certificates from a http response.
117  * Will return APR_ENOENT if content-type is not recognized (currently
118  * supports only "application/pem-certificate-chain" and "application/pkix-cert").
119  * @param chain    must be non-NULL, retrieved certificates will be added.
120  */
121 apr_status_t md_cert_chain_read_http(struct apr_array_header_t *chain,
122                                      apr_pool_t *pool, const struct md_http_response_t *res);
123 
124 md_cert_state_t md_cert_state_get(const md_cert_t *cert);
125 int md_cert_is_valid_now(const md_cert_t *cert);
126 int md_cert_has_expired(const md_cert_t *cert);
127 int md_cert_covers_domain(md_cert_t *cert, const char *domain_name);
128 int md_cert_covers_md(md_cert_t *cert, const struct md_t *md);
129 int md_cert_must_staple(const md_cert_t *cert);
130 apr_time_t md_cert_get_not_after(const md_cert_t *cert);
131 apr_time_t md_cert_get_not_before(const md_cert_t *cert);
132 
133 apr_status_t md_cert_get_issuers_uri(const char **puri, const md_cert_t *cert, apr_pool_t *p);
134 apr_status_t md_cert_get_alt_names(apr_array_header_t **pnames, const md_cert_t *cert, apr_pool_t *p);
135 
136 apr_status_t md_cert_to_base64url(const char **ps64, const md_cert_t *cert, apr_pool_t *p);
137 apr_status_t md_cert_from_base64url(md_cert_t **pcert, const char *s64, apr_pool_t *p);
138 
139 apr_status_t md_cert_to_sha256_digest(struct md_data **pdigest, const md_cert_t *cert, apr_pool_t *p);
140 apr_status_t md_cert_to_sha256_fingerprint(const char **pfinger, const md_cert_t *cert, apr_pool_t *p);
~~~

### modules/md/md_curl.c

~~~diff
--- a/modules/md/md_curl.c
+++ b/modules/md/md_curl.c
@@ -22,6 +22,7 @@
 #include <apr_strings.h>
 #include <apr_buckets.h>
 
+#include "md.h"
 #include "md_http.h"
 #include "md_log.h"
 #include "md_util.h"
@@ -64,6 +65,7 @@ static size_t req_data_cb(void *data, si
     apr_bucket_brigade *body = baton;
     size_t blen, read_len = 0, max_len = len * nmemb;
     const char *bdata;
+    char *rdata = data;
     apr_bucket *b;
     apr_status_t rv;
     
@@ -81,9 +83,10 @@ static size_t req_data_cb(void *data, si
                     apr_bucket_split(b, max_len);
                     blen = max_len;
                 }
-                memcpy(data, bdata, blen);
+                memcpy(rdata, bdata, blen);
                 read_len += blen;
                 max_len -= blen;
+                rdata += blen;
             }
             else {
                 body = NULL;
@@ -242,6 +245,7 @@ static apr_status_t internals_setup(md_h
     md_curl_internals_t *internals;
     CURL *curl;
     apr_status_t rv = APR_SUCCESS;
+    long ssl_options = 0;
 
     curl = md_http_get_impl_data(req->http);
     if (!curl) {
@@ -251,17 +255,19 @@ static apr_status_t internals_setup(md_h
             rv = APR_EGENERAL;
             goto leave;
         }
-        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
-        curl_easy_setopt(curl, CURLOPT_HEADERDATA, NULL);
-        curl_easy_setopt(curl, CURLOPT_READFUNCTION, req_data_cb);
-        curl_easy_setopt(curl, CURLOPT_READDATA, NULL);
-        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, resp_data_cb);
-        curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
     }
     else {
         md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, req->pool, "reusing curl instance from http");
+        curl_easy_reset(curl);
     }
 
+    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
+    curl_easy_setopt(curl, CURLOPT_HEADERDATA, NULL);
+    curl_easy_setopt(curl, CURLOPT_READFUNCTION, req_data_cb);
+    curl_easy_setopt(curl, CURLOPT_READDATA, NULL);
+    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, resp_data_cb);
+    curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
+
     internals = apr_pcalloc(req->pool, sizeof(*internals));
     internals->curl = curl;
         
@@ -272,13 +278,13 @@ static apr_status_t internals_setup(md_h
     internals->response->body = apr_brigade_create(req->pool, req->bucket_alloc);
     
     curl_easy_setopt(curl, CURLOPT_URL, req->url);
-    if (!apr_strnatcasecmp("GET", req->method)) {
+    if (!apr_cstr_casecmp("GET", req->method)) {
         /* nop */
     }
-    else if (!apr_strnatcasecmp("HEAD", req->method)) {
+    else if (!apr_cstr_casecmp("HEAD", req->method)) {
         curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
     }
-    else if (!apr_strnatcasecmp("POST", req->method)) {
+    else if (!apr_cstr_casecmp("POST", req->method)) {
         curl_easy_setopt(curl, CURLOPT_POST, 1L);
     }
     else {
@@ -300,6 +306,15 @@ static apr_status_t internals_setup(md_h
     }
     if (req->ca_file) {
         curl_easy_setopt(curl, CURLOPT_CAINFO, req->ca_file);
+        /* for a custom CA, allow certificates checking to ignore the
+         * Schannel error CRYPT_E_NO_REVOCATION_CHECK (could be a missing OCSP
+         * responder URL in the certs???). See issue #361 */
+#ifdef CURLSSLOPT_NO_REVOKE
+        ssl_options |= CURLSSLOPT_NO_REVOKE;
+#endif
+    }
+    if (req->unix_socket_path) {
+        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, req->unix_socket_path);
     }
 
     if (req->body_len >= 0) {
@@ -335,7 +350,10 @@ static apr_status_t internals_setup(md_h
         curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_debug_log);
         curl_easy_setopt(curl, CURLOPT_DEBUGDATA, req);
     }
-    
+
+    if (ssl_options)
+        curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, ssl_options);
+
 leave:
     req->internals = (APR_SUCCESS == rv)? internals : NULL;
     return rv;
@@ -351,6 +369,9 @@ static apr_status_t update_status(md_htt
         rv = curl_status(curl_easy_getinfo(internals->curl, CURLINFO_RESPONSE_CODE, &l));
         if (APR_SUCCESS == rv) {
             internals->response->status = (int)l;
+            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, req->pool,
+                          "req[%d]: http status is %d",
+                          req->id, internals->response->status);
         }
     }
     return rv;
@@ -433,33 +454,41 @@ static void add_to_curlm(md_http_request
 {
     md_curl_internals_t *inter
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 14..45
14  * limitations under the License.
15  */
16  
17 #include <assert.h>
18 
19 #include <curl/curl.h>
20 
21 #include <apr_lib.h>
22 #include <apr_strings.h>
23 #include <apr_buckets.h>
24 
25 #include "md_http.h"
26 #include "md_log.h"
27 #include "md_curl.h"
28 
29 /**************************************************************************************************/
30 /* md_http curl implementation */
31 
32 
33 static apr_status_t curl_status(int curl_code)
34 {
35     switch (curl_code) {
36         case CURLE_OK:                   return APR_SUCCESS;
37         case CURLE_UNSUPPORTED_PROTOCOL: return APR_ENOTIMPL; 
38         case CURLE_NOT_BUILT_IN:         return APR_ENOTIMPL; 
39         case CURLE_URL_MALFORMAT:        return APR_EINVAL;
40         case CURLE_COULDNT_RESOLVE_PROXY:return APR_ECONNREFUSED;
41         case CURLE_COULDNT_RESOLVE_HOST: return APR_ECONNREFUSED;
42         case CURLE_COULDNT_CONNECT:      return APR_ECONNREFUSED;
43         case CURLE_REMOTE_ACCESS_DENIED: return APR_EACCES;
44         case CURLE_OUT_OF_MEMORY:        return APR_ENOMEM;
45         case CURLE_OPERATION_TIMEDOUT:   return APR_TIMEUP;

Focal lines 56..87
56     const char *bdata;
57     apr_bucket *b;
58     apr_status_t rv;
59     
60     while (body && !APR_BRIGADE_EMPTY(body) && max_len > 0) {
61         b = APR_BRIGADE_FIRST(body);
62         if (APR_BUCKET_IS_METADATA(b)) {
63             if (APR_BUCKET_IS_EOS(b)) {
64                 body = NULL;
65             }
66         }
67         else {
68             rv = apr_bucket_read(b, &bdata, &blen, APR_BLOCK_READ);
69             if (rv == APR_SUCCESS) {
70                 if (blen > max_len) {
71                     apr_bucket_split(b, max_len);
72                     blen = max_len;
73                 }
74                 memcpy(data, bdata, blen);
75                 read_len += blen;
76                 max_len -= blen;
77             }
78             else {
79                 body = NULL;
80                 if (!APR_STATUS_IS_EOF(rv)) {
81                     /* everything beside EOF is an error */
82                     read_len = CURL_READFUNC_ABORT;
83                 }
84             }
85             
86         }
87         apr_bucket_delete(b);

Focal lines 73..104
73                 }
74                 memcpy(data, bdata, blen);
75                 read_len += blen;
76                 max_len -= blen;
77             }
78             else {
79                 body = NULL;
80                 if (!APR_STATUS_IS_EOF(rv)) {
81                     /* everything beside EOF is an error */
82                     read_len = CURL_READFUNC_ABORT;
83                 }
84             }
85             
86         }
87         apr_bucket_delete(b);
88     }
89     
90     return read_len;
91 }
92 
93 static size_t resp_data_cb(void *data, size_t len, size_t nmemb, void *baton)
94 {
95     md_http_response_t *res = baton;
96     size_t blen = len * nmemb;
97     apr_status_t rv;
98     
99     if (res->body) {
100         if (res->req->resp_limit) {
101             apr_off_t body_len = 0;
102             apr_brigade_length(res->body, 0, &body_len);
103             if (body_len + (apr_off_t)len > res->req->resp_limit) {
104                 return 0; /* signal curl failure */
~~~

### modules/md/md_http.c

~~~diff
--- a/modules/md/md_http.c
+++ b/modules/md/md_http.c
@@ -33,6 +33,7 @@ struct md_http_t {
     void *impl_data;         /* to be used by the implementation */
     const char *user_agent;
     const char *proxy_url;
+    const char *unix_socket_path;
     md_http_timeouts_t timeout;
     const char *ca_file;
 };
@@ -91,6 +92,25 @@ apr_status_t md_http_create(md_http_t **
     return APR_SUCCESS;
 }
 
+apr_status_t md_http_clone(md_http_t **phttp,
+                           apr_pool_t *p, md_http_t *source_http)
+{
+    apr_status_t rv;
+
+    rv = md_http_create(phttp, p, source_http->user_agent, source_http->proxy_url);
+    if (APR_SUCCESS == rv) {
+        (*phttp)->resp_limit = source_http->resp_limit;
+        (*phttp)->timeout = source_http->timeout;
+        if (source_http->unix_socket_path) {
+            (*phttp)->unix_socket_path = apr_pstrdup(p, source_http->unix_socket_path);
+        }
+        if (source_http->ca_file) {
+            (*phttp)->ca_file = apr_pstrdup(p, source_http->ca_file);
+        }
+    }
+    return rv;
+}
+
 void md_http_set_impl_data(md_http_t *http, void *data)
 {
     http->impl_data = data;
@@ -143,6 +163,11 @@ void md_http_set_ca_file(md_http_t *http
     http->ca_file = ca_file;
 }
 
+void md_http_set_unix_socket_path(md_http_t *http, const char *path)
+{
+    http->unix_socket_path = path;
+}
+
 static apr_status_t req_set_body(md_http_request_t *req, const char *content_type,
                                  apr_bucket_brigade *body, apr_off_t body_len,
                                  int detect_len)
@@ -177,7 +202,6 @@ static apr_status_t req_set_body_data(md
         bbody = apr_brigade_create(req->pool, req->http->bucket_alloc);
         rv = apr_brigade_write(bbody, NULL, NULL, body->data, body->len);
         if (rv != APR_SUCCESS) {
-            md_http_req_destroy(req);
             return rv;
         }
     }
@@ -211,17 +235,20 @@ static apr_status_t req_create(md_http_r
     req->proxy_url = http->proxy_url;
     req->timeout = http->timeout;
     req->ca_file = http->ca_file;
+    req->unix_socket_path = http->unix_socket_path;
     *preq = req;
     return rv;
 }
 
 void md_http_req_destroy(md_http_request_t *req) 
 {
-    if (req->internals) {
-        req->http->impl->req_cleanup(req);
-        req->internals = NULL;
+    if (req) {
+        if (req->internals) {
+            req->http->impl->req_cleanup(req);
+            req->internals = NULL;
+        }
+        apr_pool_destroy(req->pool);
     }
-    apr_pool_destroy(req->pool);
 }
 
 void md_http_set_on_status_cb(md_http_request_t *req, md_http_status_cb *cb, void *baton)
@@ -308,10 +335,16 @@ apr_status_t md_http_POSTd_create(md_htt
     apr_status_t rv;
     
     rv = req_create(&req, http, "POST", url, headers);
+    if (APR_SUCCESS != rv) goto cleanup;
+    rv = req_set_body_data(req, content_type, body);
+cleanup:
     if (APR_SUCCESS == rv) {
-        rv = req_set_body_data(req, content_type, body);
+        *preq = req;
+    }
+    else {
+        *preq = NULL;
+        md_http_req_destroy(req);
     }
-    *preq = (APR_SUCCESS == rv)? req : NULL;
     return rv;
 }
 

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 25..56
25 
26 struct md_http_t {
27     apr_pool_t *pool;
28     apr_bucket_alloc_t *bucket_alloc;
29     apr_off_t resp_limit;
30     md_http_impl_t *impl;
31     const char *user_agent;
32     const char *proxy_url;
33 };
34 
35 static md_http_impl_t *cur_impl;
36 static int cur_init_done;
37 
38 void md_http_use_implementation(md_http_impl_t *impl)
39 {
40     if (cur_impl != impl) {
41         cur_impl = impl;
42         cur_init_done = 0;
43     }
44 }
45 
46 apr_status_t md_http_create(md_http_t **phttp, apr_pool_t *p, const char *user_agent,
47                             const char *proxy_url)
48 {
49     md_http_t *http;
50     apr_status_t rv = APR_SUCCESS;
51 
52     if (!cur_impl) {
53         *phttp = NULL;
54         return APR_ENOTIMPL;
55     }
56     

Focal lines 83..114
83 
84 static apr_status_t req_create(md_http_request_t **preq, md_http_t *http, 
85                                const char *method, const char *url, struct apr_table_t *headers,
86                                md_http_cb *cb, void *baton)
87 {
88     md_http_request_t *req;
89     apr_pool_t *pool;
90     apr_status_t rv;
91     
92     rv = apr_pool_create(&pool, http->pool);
93     if (rv != APR_SUCCESS) {
94         return rv;
95     }
96     
97     req = apr_pcalloc(pool, sizeof(*req));
98     req->pool = pool;
99     req->bucket_alloc = http->bucket_alloc;
100     req->http = http;
101     req->method = method;
102     req->url = url;
103     req->headers = headers? apr_table_copy(req->pool, headers) : apr_table_make(req->pool, 5);
104     req->resp_limit = http->resp_limit;
105     req->cb = cb;
106     req->baton = baton;
107     req->user_agent = http->user_agent;
108     req->proxy_url = http->proxy_url;
109 
110     *preq = req;
111     return rv;
112 }
113 
114 void md_http_req_destroy(md_http_request_t *req) 

Focal lines 135..166
135             return rv;
136         }
137     }
138     
139     if (req->body_len == 0 && apr_strnatcasecmp("GET", req->method)) {
140         apr_table_setn(req->headers, "Content-Length", "0");
141     }
142     else if (req->body_len > 0) {
143         apr_table_setn(req->headers, "Content-Length", apr_off_t_toa(req->pool, req->body_len));
144     }
145     
146     return req->http->impl->perform(req);
147 }
148 
149 apr_status_t md_http_GET(struct md_http_t *http, 
150                          const char *url, struct apr_table_t *headers,
151                          md_http_cb *cb, void *baton)
152 {
153     md_http_request_t *req;
154     apr_status_t rv;
155     
156     rv = req_create(&req, http, "GET", url, headers, cb, baton);
157     if (rv != APR_SUCCESS) {
158         return rv;
159     }
160     
161     return schedule(req, NULL, 0);
162 }
163 
164 apr_status_t md_http_HEAD(struct md_http_t *http, 
165                           const char *url, struct apr_table_t *headers,
166                           md_http_cb *cb, void *baton)
~~~

### modules/md/md_http.h

~~~diff
--- a/modules/md/md_http.h
+++ b/modules/md/md_http.h
@@ -65,6 +65,7 @@ struct md_http_request_t {
     const char *user_agent;
     const char *proxy_url;
     const char *ca_file;
+    const char *unix_socket_path;
     apr_table_t *headers;
     struct apr_bucket_brigade *body;
     apr_off_t body_len;
@@ -87,6 +88,13 @@ apr_status_t md_http_create(md_http_t **
 void md_http_set_response_limit(md_http_t *http, apr_off_t resp_limit);
 
 /**
+ * Clone a http instance, inheriting all settings from source_http.
+ * The cloned instance is not tied in any way to the source.
+ */
+apr_status_t md_http_clone(md_http_t **phttp,
+                           apr_pool_t *p, md_http_t *source_http);
+
+/**
  * Set the timeout for the complete request. This needs to take everything from
  * DNS looksups, to conntects, to transfer of all data into account and should
  * be sufficiently large.
@@ -118,6 +126,12 @@ void md_http_set_stalling(md_http_reques
 void md_http_set_ca_file(md_http_t *http, const char *ca_file);
 
 /**
+ * Set the path of a unix domain socket for use instead of TCP
+ * in a connection. Disable by providing NULL as path.
+ */
+void md_http_set_unix_socket_path(md_http_t *http, const char *path);
+
+/**
  * Perform the request. Then this function returns, the request and
  * all its memory has been freed and must no longer be used.
  */

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 57..88
57                             const char *proxy_url);
58 
59 void md_http_set_response_limit(md_http_t *http, apr_off_t resp_limit);
60 
61 apr_status_t md_http_GET(md_http_t *http, 
62                          const char *url, struct apr_table_t *headers,
63                          md_http_cb *cb, void *baton);
64 
65 apr_status_t md_http_HEAD(md_http_t *http, 
66                           const char *url, struct apr_table_t *headers,
67                           md_http_cb *cb, void *baton);
68 
69 apr_status_t md_http_POST(md_http_t *http, const char *url, 
70                           struct apr_table_t *headers, const char *content_type, 
71                           struct apr_bucket_brigade *body,
72                           md_http_cb *cb, void *baton);
73 
74 apr_status_t md_http_POSTd(md_http_t *http, const char *url, 
75                            struct apr_table_t *headers, const char *content_type, 
76                            const char *data, size_t data_len, 
77                            md_http_cb *cb, void *baton);
78 
79 void md_http_req_destroy(md_http_request_t *req);
80 
81 /**************************************************************************************************/
82 /* interface to implementation */
83 
84 typedef apr_status_t md_http_init_cb(void);
85 typedef void md_http_req_cleanup_cb(md_http_request_t *req);
86 typedef apr_status_t md_http_perform_cb(md_http_request_t *req);
87 
88 typedef struct md_http_impl_t md_http_impl_t;

Focal lines 79..99
79 void md_http_req_destroy(md_http_request_t *req);
80 
81 /**************************************************************************************************/
82 /* interface to implementation */
83 
84 typedef apr_status_t md_http_init_cb(void);
85 typedef void md_http_req_cleanup_cb(md_http_request_t *req);
86 typedef apr_status_t md_http_perform_cb(md_http_request_t *req);
87 
88 typedef struct md_http_impl_t md_http_impl_t;
89 struct md_http_impl_t {
90     md_http_init_cb *init;
91     md_http_req_cleanup_cb *req_cleanup;
92     md_http_perform_cb *perform;
93 };
94 
95 void md_http_use_implementation(md_http_impl_t *impl);
96 
97 
98 
99 #endif /* md_http_h */

Focal lines 100..99

~~~

### modules/md/md_json.c

~~~diff
--- a/modules/md/md_json.c
+++ b/modules/md/md_json.c
@@ -176,7 +176,7 @@ static apr_status_t jselect_add(json_t *
     aj = json_object_get(j, key);
     if (!aj) {
         aj = json_array();
-        json_object_set(j, key, aj);
+        json_object_set_new(j, key, aj);
     }
     
     if (!json_is_array(aj)) {
@@ -202,7 +202,7 @@ static apr_status_t jselect_insert(json_
     aj = json_object_get(j, key);
     if (!aj) {
         aj = json_array();
-        json_object_set(j, key, aj);
+        json_object_set_new(j, key, aj);
     }
     
     if (!json_is_array(aj)) {
@@ -1186,14 +1186,18 @@ apr_status_t md_json_read_http(md_json_t
 {
     apr_status_t rv = APR_ENOENT;
     const char *ctype, *p;
+    apr_size_t ctype_len;
 
     *pjson = NULL;
     if (!res->body) goto cleanup;
     ctype = md_util_parse_ct(res->req->pool, apr_table_get(res->headers, "content-type"));
     if (!ctype) goto cleanup;
-    p = ctype + strlen(ctype) +1;
-    if (!strcmp(p - sizeof("/json"), "/json")
-        || !strcmp(p - sizeof("+json"), "+json")) {
+    ctype_len = strlen(ctype);
+    if (ctype_len < sizeof("/json")) goto cleanup;
+    p = ctype + ctype_len + 1; /* point to the terminating 0 */
+    if (!strcmp(p - sizeof("/json"), "/json") ||
+        !strcmp(p - sizeof("+json"), "+json") ||
+        !strcmp(ctype, "text/plain")) {
         rv = md_json_readb(pjson, pool, res->body);
     }
 cleanup:
@@ -1264,7 +1268,7 @@ apr_status_t md_json_set_timeperiod(cons
     const char *key;
     apr_status_t rv;
     
-    if (!tp || tp->start || tp->end) {
+    if (tp && tp->start && tp->end) {
         jn = json_object();
         apr_rfc822_date(ts, tp->start);
         json_object_set_new(jn, "from", json_string(ts));

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 168..199
168     j = jselect_parent(&key, 1, json, ap);
169     
170     if (!j || !json_is_object(j)) {
171         json_decref(val);
172         return APR_EINVAL;
173     }
174     
175     aj = json_object_get(j, key);
176     if (!aj) {
177         aj = json_array();
178         json_object_set_new(j, key, aj);
179     }
180     
181     if (!json_is_array(aj)) {
182         json_decref(val);
183         return APR_EINVAL;
184     }
185 
186     json_array_append(aj, val);
187     return APR_SUCCESS;
188 }
189 
190 static apr_status_t jselect_insert(json_t *val, size_t index, md_json_t *json, va_list ap)
191 {
192     const char *key;
193     json_t *j, *aj;
194     
195     j = jselect_parent(&key, 1, json, ap);
196     
197     if (!j || !json_is_object(j)) {
198         json_decref(val);
199         return APR_EINVAL;

Focal lines 194..225
194     
195     j = jselect_parent(&key, 1, json, ap);
196     
197     if (!j || !json_is_object(j)) {
198         json_decref(val);
199         return APR_EINVAL;
200     }
201     
202     aj = json_object_get(j, key);
203     if (!aj) {
204         aj = json_array();
205         json_object_set_new(j, key, aj);
206     }
207     
208     if (!json_is_array(aj)) {
209         json_decref(val);
210         return APR_EINVAL;
211     }
212 
213     if (json_array_size(aj) <= index) {
214         json_array_append(aj, val);
215     }
216     else {
217         json_array_insert(aj, index, val);
218     }
219     return APR_SUCCESS;
220 }
221 
222 static apr_status_t jselect_set(json_t *val, md_json_t *json, va_list ap)
223 {
224     const char *key;
225     json_t *j;

Focal lines 1137..1136

~~~

### modules/md/md_log.h

~~~diff
--- a/modules/md/md_log.h
+++ b/modules/md/md_log.h
@@ -38,6 +38,10 @@ typedef enum {
 
 #define MD_LOG_MARK     __FILE__,__LINE__
 
+#ifndef APLOGNO
+#define APLOGNO(n)              "AH" #n ": "
+#endif
+
 const char *md_log_level_name(md_log_level_t level);
 
 int md_log_is_level(apr_pool_t *p, md_log_level_t level);

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 30..56
30     MD_LOG_TRACE2, 
31     MD_LOG_TRACE3, 
32     MD_LOG_TRACE4, 
33     MD_LOG_TRACE5, 
34     MD_LOG_TRACE6, 
35     MD_LOG_TRACE7, 
36     MD_LOG_TRACE8, 
37 } md_log_level_t;
38 
39 #define MD_LOG_MARK     __FILE__,__LINE__
40 
41 const char *md_log_level_name(md_log_level_t level);
42 
43 int md_log_is_level(apr_pool_t *p, md_log_level_t level);
44 
45 void md_log_perror(const char *file, int line, md_log_level_t level, 
46                    apr_status_t rv, apr_pool_t *p, const char *fmt, ...)
47                                 __attribute__((format(printf,6,7)));
48 
49 typedef int md_log_level_cb(void *baton, apr_pool_t *p, md_log_level_t level);
50 
51 typedef void md_log_print_cb(const char *file, int line, md_log_level_t level, 
52                 apr_status_t rv, void *baton, apr_pool_t *p, const char *fmt, va_list ap);
53 
54 void md_log_set(md_log_level_cb *level_cb, md_log_print_cb *print_cb, void *baton);
55 
56 #endif /* md_log_h */
~~~

### modules/md/md_ocsp.c

~~~diff
--- a/modules/md/md_ocsp.c
+++ b/modules/md/md_ocsp.c
@@ -32,13 +32,6 @@
 #include <openssl/pem.h>
 #include <openssl/x509v3.h>
 
-#if defined(LIBRESSL_VERSION_NUMBER)
-/* Missing from LibreSSL */
-#define MD_USE_OPENSSL_PRE_1_1_API (LIBRESSL_VERSION_NUMBER < 0x2070000f)
-#else /* defined(LIBRESSL_VERSION_NUMBER) */
-#define MD_USE_OPENSSL_PRE_1_1_API (OPENSSL_VERSION_NUMBER < 0x10100000L)
-#endif
-
 #include "md.h"
 #include "md_crypt.h"
 #include "md_event.h"
@@ -65,6 +58,7 @@ struct md_ocsp_reg_t {
     md_timeslice_t renew_window;
     md_job_notify_cb *notify;
     void *notify_ctx;
+    apr_time_t min_delay;
 };
 
 typedef struct md_ocsp_status_t md_ocsp_status_t; 
@@ -196,6 +190,7 @@ static apr_status_t ostat_from_json(md_o
     md_timeperiod_t valid;
     apr_status_t rv = APR_ENOENT;
     
+    memset(&valid, 0, sizeof(valid));
     memset(resp_der, 0, sizeof(*resp_der));
     memset(resp_valid, 0, sizeof(*resp_valid));
     s = md_json_dups(p, json, MD_KEY_VALID, MD_KEY_FROM, NULL);
@@ -279,7 +274,8 @@ static apr_status_t ocsp_reg_cleanup(voi
 
 apr_status_t md_ocsp_reg_make(md_ocsp_reg_t **preg, apr_pool_t *p, md_store_t *store, 
                               const md_timeslice_t *renew_window,
-                              const char *user_agent, const char *proxy_url)
+                              const char *user_agent, const char *proxy_url,
+                              apr_time_t min_delay)
 {
     md_ocsp_reg_t *reg;
     apr_status_t rv = APR_SUCCESS;
@@ -296,6 +292,7 @@ apr_status_t md_ocsp_reg_make(md_ocsp_re
     reg->id_by_external_id = apr_hash_make(p);
     reg->ostat_by_id = apr_hash_make(p);
     reg->renew_window = *renew_window;
+    reg->min_delay = min_delay;
     
     rv = apr_thread_mutex_create(&reg->mutex, APR_THREAD_MUTEX_NESTED, p);
     if (APR_SUCCESS != rv) goto cleanup;
@@ -338,7 +335,7 @@ apr_status_t md_ocsp_prime(md_ocsp_reg_t
                   "md[%s]: getting ocsp responder from cert", name);
     rv = md_cert_get_ocsp_responder_url(&ostat->responder_url, reg->p, cert);
     if (APR_SUCCESS != rv) {
-        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, reg->p,
+        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, reg->p,
                       "md[%s]: certificate with serial %s has no OCSP responder URL",
                       name, md_cert_get_serial_number(cert, reg->p));
         goto cleanup;
@@ -449,7 +446,7 @@ static void ocsp_get_meta(md_ocsp_cert_s
 {
     apr_thread_mutex_lock(reg->mutex);
     if (ostat->resp_der.len <= 0) {
-        /* No resonse known, check the store if out watchdog retrieved one 
+        /* No response known, check the store if out watchdog retrieved one 
          * in the meantime. */
         ocsp_status_refresh(ostat, p);
     }
@@ -535,7 +532,7 @@ static const char *certid_summary(const
         bn = ASN1_INTEGER_to_BN(aserial, NULL);
         s = BN_bn2hex(bn);
         serial = apr_pstrdup(p, s);
-        OPENSSL_free((void*)bn);
+        BN_free(bn);
         OPENSSL_free((void*)s);
     }
     return apr_psprintf(p, "certid[der=%s, issuer=%s, key=%s, serial=%s]",
@@ -560,7 +557,9 @@ static const char *single_resp_summary(O
     ASN1_GENERALIZEDTIME *bup = NULL, *bnextup = NULL;
     md_timeperiod_t valid;
     
-#if MD_USE_OPENSSL_PRE_1_1_API
+#if OPENSSL_VERSION_NUMBER < 0x10100000L \
+    || (defined(LIBRESSL_VERSION_NUMBER) \
+        && LIBRESSL_VERSION_NUMBER < 0x2070000f)
     certid = resp->certId;
 #else
     certid = OCSP_SINGLERESP_get0_id(resp);
@@ -640,7 +639,7 @@ static apr_status_t ostat_on_resp(const
     switch ((n = OCSP_check_nonce(ostat->ocsp_req, basic_resp))) {
         case 1:
             md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, req->pool,
-                          "req[%d]: OCSP respoonse nonce does match", req->id);
+                          "req[%d]: OCSP response nonce does match", req->id);
             break;
         case 0:
             rv = APR_EINVAL;
@@ -650,7 +649,7 @@ static apr_status_t ostat_on_resp(const
             
         case -1:
             md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, req->pool,
-                          "req[%d]: OCSP respoonse did not return the nonce", req->id);
+                          "req[%d]: OCSP response did not return the nonce", req->id);
             break;
         default:
             break;
@@ -680,12 +679,6 @@ static apr_status_t ostat_on_resp(const
         md_result_log(update->result, MD_LOG_DEBUG);
         goto cleanup;
     }
-    
~~~

Source file missing in Focal.

### modules/md/md_ocsp.h

~~~diff
--- a/modules/md/md_ocsp.h
+++ b/modules/md/md_ocsp.h
@@ -38,7 +38,8 @@ typedef struct md_ocsp_reg_t md_ocsp_reg
 apr_status_t md_ocsp_reg_make(md_ocsp_reg_t **preg, apr_pool_t *p,
                               struct md_store_t *store, 
                               const md_timeslice_t *renew_window,
-                              const char *user_agent, const char *proxy_url);
+                              const char *user_agent, const char *proxy_url,
+                              apr_time_t min_delay);
 
 apr_status_t md_ocsp_init_id(struct md_data_t *id, apr_pool_t *p, const md_cert_t *cert);
 

~~~

Source file missing in Focal.

### modules/md/md_reg.c

~~~diff
--- a/modules/md/md_reg.c
+++ b/modules/md/md_reg.c
@@ -31,6 +31,7 @@
 #include "md_json.h"
 #include "md_result.h"
 #include "md_reg.h"
+#include "md_ocsp.h"
 #include "md_store.h"
 #include "md_status.h"
 #include "md_util.h"
@@ -52,6 +53,10 @@ struct md_reg_t {
     md_timeslice_t *warn_window;
     md_job_notify_cb *notify;
     void *notify_ctx;
+    apr_time_t min_delay;
+    int retry_failover;
+    int use_store_locks;
+    apr_time_t lock_wait_timeout;
 };
 
 /**************************************************************************************************/
@@ -75,11 +80,25 @@ static apr_status_t load_props(md_reg_t
     else if (APR_STATUS_IS_ENOENT(rv)) {
         rv = APR_SUCCESS;
     }
+    else {
+        apr_status_t rv2;
+        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, p,
+                      "removing md/%s on error loading it", MD_FN_HTTPD_JSON);
+        rv2 = md_store_remove(reg->store, MD_SG_NONE, NULL, MD_FN_HTTPD_JSON,
+                              p, TRUE);
+        if (rv2 != APR_SUCCESS)
+          md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p,
+                        "error removing md/%s", MD_FN_HTTPD_JSON);
+        else
+          rv = APR_SUCCESS;
+    }
     return rv;
 }
 
 apr_status_t md_reg_create(md_reg_t **preg, apr_pool_t *p, struct md_store_t *store,
-                           const char *proxy_url, const char *ca_file)
+                           const char *proxy_url, const char *ca_file,
+                           apr_time_t min_delay, int retry_failover,
+                           int use_store_locks, apr_time_t lock_wait_timeout)
 {
     md_reg_t *reg;
     apr_status_t rv;
@@ -92,8 +111,12 @@ apr_status_t md_reg_create(md_reg_t **pr
     reg->can_http = 1;
     reg->can_https = 1;
     reg->proxy_url = proxy_url? apr_pstrdup(p, proxy_url) : NULL;
-    reg->ca_file = (ca_file && apr_strnatcasecmp("none", ca_file))?
+    reg->ca_file = (ca_file && apr_cstr_casecmp("none", ca_file))?
                     apr_pstrdup(p, ca_file) : NULL;
+    reg->min_delay = min_delay;
+    reg->retry_failover = retry_failover;
+    reg->use_store_locks = use_store_locks;
+    reg->lock_wait_timeout = lock_wait_timeout;
 
     md_timeslice_create(&reg->renew_window, p, MD_TIME_LIFE_NORM, MD_TIME_RENEW_WINDOW_DEF); 
     md_timeslice_create(&reg->warn_window, p, MD_TIME_LIFE_NORM, MD_TIME_WARN_WINDOW_DEF); 
@@ -163,12 +186,17 @@ static apr_status_t check_values(md_reg_
         }
     }
     
-    if ((MD_UPD_CA_URL & fields) && md->ca_url) { /* setting to empty is ok */
-        rv = md_util_abs_uri_check(p, md->ca_url, &err);
-        if (err) {
-            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
-                          "CA url for %s invalid (%s): %s", md->name, err, md->ca_url);
-            return APR_EINVAL;
+    if ((MD_UPD_CA_URL & fields) && md->ca_urls) { /* setting to empty is ok */
+        int i;
+        const char *url;
+        for (i = 0; i < md->ca_urls->nelts; ++i) {
+            url = APR_ARRAY_IDX(md->ca_urls, i, const char*);
+            rv = md_util_abs_uri_check(p, url, &err);
+            if (err) {
+                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p,
+                              "CA url for %s invalid (%s): %s", md->name, err, url);
+                return APR_EINVAL;
+            }
         }
     }
     
@@ -204,11 +232,21 @@ static apr_status_t state_init(md_reg_t
     const md_cert_t *cert;
     const md_pkey_spec_t *spec;
     apr_status_t rv = APR_SUCCESS;
-    int i;
+    int i, is_static = (md->cert_files && md->cert_files->nelts);
 
     if (md->renew_window == NULL) md->renew_window = reg->renew_window;
     if (md->warn_window == NULL) md->warn_window = reg->warn_window;
-    
+
+    if (is_static) {
+        if (md->renew_mode == MD_RENEW_AUTO)
+            md->renew_mode = MD_RENEW_MANUAL;
+    }
+
+    if (md->domains && md->domains->pool != p) {
+        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p,
+                      "md{%s}: state_init called with foreign pool", md->name);
+    }
+
     for (i = 0; i < md_cert_count(md); ++i) {
         spec = md_pkeys_spec_get(md->pks, i);
         md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, p,
@@ -243,7 +281,7 @@ static apr_status_t state_init(md_reg_t
         }
         else {
             state = MD_S_ERROR;
-            state_descr = "error intializing";
+            state_descr = "error initializing";
             md_log_perror(MD_LOG_MARK, MD_LOG_
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 23..54
23 #include <apr_hash.h>
24 #include <apr_strings.h>
25 #include <apr_uri.h>
26 
27 #include "md.h"
28 #include "md_crypt.h"
29 #include "md_log.h"
30 #include "md_json.h"
31 #include "md_result.h"
32 #include "md_reg.h"
33 #include "md_store.h"
34 #include "md_status.h"
35 #include "md_util.h"
36 
37 #include "md_acme.h"
38 #include "md_acme_acct.h"
39 
40 struct md_reg_t {
41     apr_pool_t *p;
42     struct md_store_t *store;
43     struct apr_hash_t *protos;
44     struct apr_hash_t *certs;
45     int can_http;
46     int can_https;
47     const char *proxy_url;
48     int domains_frozen;
49     const md_timeslice_t *renew_window;
50     const md_timeslice_t *warn_window;
51 };
52 
53 /**************************************************************************************************/
54 /* life cycle */

Focal lines 44..75
44     struct apr_hash_t *certs;
45     int can_http;
46     int can_https;
47     const char *proxy_url;
48     int domains_frozen;
49     const md_timeslice_t *renew_window;
50     const md_timeslice_t *warn_window;
51 };
52 
53 /**************************************************************************************************/
54 /* life cycle */
55 
56 static apr_status_t load_props(md_reg_t *reg, apr_pool_t *p)
57 {
58     md_json_t *json;
59     apr_status_t rv;
60     
61     rv = md_store_load(reg->store, MD_SG_NONE, NULL, MD_FN_HTTPD_JSON, 
62                        MD_SV_JSON, (void**)&json, p);
63     if (APR_SUCCESS == rv) {
64         if (md_json_has_key(json, MD_KEY_PROTO, MD_KEY_HTTP, NULL)) {
65             reg->can_http = md_json_getb(json, MD_KEY_PROTO, MD_KEY_HTTP, NULL);
66         }
67         if (md_json_has_key(json, MD_KEY_PROTO, MD_KEY_HTTPS, NULL)) {
68             reg->can_https = md_json_getb(json, MD_KEY_PROTO, MD_KEY_HTTPS, NULL);
69         }
70     }
71     else if (APR_STATUS_IS_ENOENT(rv)) {
72         rv = APR_SUCCESS;
73     }
74     return rv;
75 }

Focal lines 67..98
67         if (md_json_has_key(json, MD_KEY_PROTO, MD_KEY_HTTPS, NULL)) {
68             reg->can_https = md_json_getb(json, MD_KEY_PROTO, MD_KEY_HTTPS, NULL);
69         }
70     }
71     else if (APR_STATUS_IS_ENOENT(rv)) {
72         rv = APR_SUCCESS;
73     }
74     return rv;
75 }
76 
77 apr_status_t md_reg_create(md_reg_t **preg, apr_pool_t *p, struct md_store_t *store,
78                            const char *proxy_url)
79 {
80     md_reg_t *reg;
81     apr_status_t rv;
82     
83     reg = apr_pcalloc(p, sizeof(*reg));
84     reg->p = p;
85     reg->store = store;
86     reg->protos = apr_hash_make(p);
87     reg->certs = apr_hash_make(p);
88     reg->can_http = 1;
89     reg->can_https = 1;
90     reg->proxy_url = proxy_url? apr_pstrdup(p, proxy_url) : NULL;
91     
92     md_timeslice_create(&reg->renew_window, p, MD_TIME_LIFE_NORM, MD_TIME_RENEW_WINDOW_DEF); 
93     md_timeslice_create(&reg->warn_window, p, MD_TIME_LIFE_NORM, MD_TIME_WARN_WINDOW_DEF); 
94     
95     if (APR_SUCCESS == (rv = md_acme_protos_add(reg->protos, p))) {
96         rv = load_props(reg, p);
97     }
98     
~~~

### modules/md/md_reg.h

~~~diff
--- a/modules/md/md_reg.h
+++ b/modules/md/md_reg.h
@@ -23,6 +23,7 @@ struct md_pkey_t;
 struct md_cert_t;
 struct md_result_t;
 struct md_pkey_spec_t;
+struct md_ocsp_reg_t;
 
 #include "md_store.h"
 
@@ -34,9 +35,18 @@ typedef struct md_reg_t md_reg_t;
 
 /**
  * Create the MD registry, using the pool and store.
+ * @param preg on APR_SUCCESS, the create md_reg_t
+ * @param pm memory pool to use for creation
+ * @param store the store to base on
+ * @param proxy_url optional URL of a proxy to use for requests
+ * @param ca_file  optioinal CA trust anchor file to use
+ * @param min_delay minimum delay between renewal attempts for a domain
+ * @param retry_failover numer of failed renewals attempt to fail over to alternate ACME ca
  */
 apr_status_t md_reg_create(md_reg_t **preg, apr_pool_t *pm, md_store_t *store,
-                           const char *proxy_url, const char *ca_file);
+                           const char *proxy_url, const char *ca_file,
+                           apr_time_t min_delay, int retry_failover,
+                           int use_store_locks, apr_time_t lock_wait_timeout);
 
 md_store_t *md_reg_store_get(md_reg_t *reg);
 
@@ -173,6 +183,14 @@ int md_reg_should_renew(md_reg_t *reg, c
  */
 apr_time_t md_reg_renew_at(md_reg_t *reg, const md_t *md, apr_pool_t *p);
 
+/* Check ACME Renewal Info, if available, for the CA recommended time
+ * (and optional reason URL) for certificate renewal.
+ * Returns 0 if not availble.
+ */
+apr_time_t md_reg_ari_renew_at(const char **purl, md_reg_t *reg,
+                               const md_t *md, struct apr_table_t *env,
+                               struct md_result_t *result, apr_pool_t *p);
+
 /**
  * Return the timestamp up to which *all* certificates for the MD can be used.
  * A value of 0 indicates that there is no certificate.
@@ -212,6 +230,8 @@ struct md_proto_driver_t {
     int can_http;
     int can_https;
     int reset;
+    int attempt;
+    int retry_failover;
     apr_interval_time_t activation_delay;
 };
 
@@ -220,6 +240,9 @@ typedef apr_status_t md_proto_renew_cb(m
 typedef apr_status_t md_proto_init_preload_cb(md_proto_driver_t *driver, struct md_result_t *result);
 typedef apr_status_t md_proto_preload_cb(md_proto_driver_t *driver, 
                                          md_store_group_t group, struct md_result_t *result);
+typedef apr_status_t md_proto_complete_md_cb(md_t *md, apr_pool_t *p);
+typedef apr_status_t md_proto_get_ari(md_proto_driver_t *driver, struct md_result_t *result,
+                                      apr_time_t *prenew_at, const char **purl);
 
 struct md_proto_t {
     const char *protocol;
@@ -227,6 +250,8 @@ struct md_proto_t {
     md_proto_renew_cb *renew;
     md_proto_init_preload_cb *init_preload;
     md_proto_preload_cb *preload;
+    md_proto_complete_md_cb *complete_md;
+    md_proto_get_ari *get_ari;
 };
 
 /**
@@ -240,11 +265,17 @@ apr_status_t md_reg_test_init(md_reg_t *
 
 /**
  * Obtain new credentials for the given managed domain in STAGING.
- *
+ * @param reg the registry instance
+ * @param md the mdomain to renew
+ * @param env global environment of settings
+ * @param reset != 0 if any previous, partial information should be wiped
+ * @param attempt the number of attempts made this far (for this md)
+ * @param result for reporting results of the renewal
+ * @param p the memory pool to use
  * @return APR_SUCCESS if new credentials have been staged successfully
  */
 apr_status_t md_reg_renew(md_reg_t *reg, const md_t *md, 
-                          struct apr_table_t *env, int reset, 
+                          struct apr_table_t *env, int reset, int attempt,
                           struct md_result_t *result, apr_pool_t *p);
 
 /**
@@ -259,9 +290,42 @@ apr_status_t md_reg_renew(md_reg_t *reg,
 apr_status_t md_reg_load_staging(md_reg_t *reg, const md_t *md, struct apr_table_t *env, 
                                  struct md_result_t *result, apr_pool_t *p);
 
+/**
+ * Check given MDomains for new data in staging areas and, if it exists, load
+ * the new credentials. On encountering errors, leave the credentails as
+ * they are.
+ */
+apr_status_t md_reg_load_stagings(md_reg_t *reg, apr_array_header_t *mds,
+                                  apr_table_t *env, apr_pool_t *p);
+
 void md_reg_set_renew_window_default(md_reg_t *reg, md_timeslice_t *renew_window);
 void md_reg_set_warn_window_default(md_reg_t *reg, md_timeslice_t *warn_window);
 
 struct md_job_t *md_reg_job_ma
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 15..46
15  */
16 
17 #ifndef mod_md_md_reg_h
18 #define mod_md_md_reg_h
19 
20 struct apr_hash_t;
21 struct apr_array_header_t;
22 struct md_store_t;
23 struct md_pkey_t;
24 struct md_cert_t;
25 struct md_result_t;
26 
27 /**
28  * A registry for managed domains with a md_store_t as persistence.
29  *
30  */
31 typedef struct md_reg_t md_reg_t;
32 
33 /**
34  * Create the MD registry, using the pool and store.
35  */
36 apr_status_t md_reg_create(md_reg_t **preg, apr_pool_t *pm, struct md_store_t *store,
37                            const char *proxy_url);
38 
39 struct md_store_t *md_reg_store_get(md_reg_t *reg);
40 
41 apr_status_t md_reg_set_props(md_reg_t *reg, apr_pool_t *p, int can_http, int can_https);
42 
43 /**
44  * Add a new md to the registry. This will check the name for uniqueness and
45  * that domain names do not overlap with already existing mds.
46  */

Focal lines 26..57
26 
27 /**
28  * A registry for managed domains with a md_store_t as persistence.
29  *
30  */
31 typedef struct md_reg_t md_reg_t;
32 
33 /**
34  * Create the MD registry, using the pool and store.
35  */
36 apr_status_t md_reg_create(md_reg_t **preg, apr_pool_t *pm, struct md_store_t *store,
37                            const char *proxy_url);
38 
39 struct md_store_t *md_reg_store_get(md_reg_t *reg);
40 
41 apr_status_t md_reg_set_props(md_reg_t *reg, apr_pool_t *p, int can_http, int can_https);
42 
43 /**
44  * Add a new md to the registry. This will check the name for uniqueness and
45  * that domain names do not overlap with already existing mds.
46  */
47 apr_status_t md_reg_add(md_reg_t *reg, md_t *md, apr_pool_t *p);
48 
49 /**
50  * Find the md, if any, that contains the given domain name. 
51  * NULL if none found.
52  */
53 md_t *md_reg_find(md_reg_t *reg, const char *domain, apr_pool_t *p);
54 
55 /**
56  * Find one md, which domain names overlap with the given md and that has a different
57  * name. There may be more than one existing md that overlaps. It is not defined

Focal lines 165..196
165 
166 /**
167  * Return if a warning should be issued about the certificate expiration. 
168  * This applies the configured warn window to the remaining lifetime of the 
169  * current certiciate. If no certificate is present, this returns 0.
170  */
171 int md_reg_should_warn(md_reg_t *reg, const md_t *md, apr_pool_t *p);
172 
173 /**************************************************************************************************/
174 /* protocol drivers */
175 
176 typedef struct md_proto_t md_proto_t;
177 
178 typedef struct md_proto_driver_t md_proto_driver_t;
179 
180 /** 
181  * Operating environment for a protocol driver. This is valid only for the
182  * duration of one run (init + renew, init + preload).
183  */
184 struct md_proto_driver_t {
185     const md_proto_t *proto;
186     apr_pool_t *p;
187     void *baton;
188     struct apr_table_t *env;
189 
190     md_reg_t *reg;
191     struct md_store_t *store;
192     const char *proxy_url;
193     const md_t *md;
194 
195     int can_http;
196     int can_https;
~~~

### modules/md/md_status.c

~~~diff
--- a/modules/md/md_status.c
+++ b/modules/md/md_status.c
@@ -47,12 +47,21 @@ static apr_status_t status_get_cert_json
     apr_status_t rv = APR_SUCCESS;
     md_timeperiod_t valid;
     md_json_t *json;
-    
+    const char *issuer_uri, *issuer_name;
+
+
     json = md_json_create(p);
+    issuer_name = md_cert_get_issuer_name(cert, p);
+    if (issuer_name)
+      md_json_sets(issuer_name, json, MD_KEY_ISSUER_NAME, NULL);
+    rv = md_cert_get_issuers_uri(&issuer_uri, cert, p);
+    if (rv == APR_SUCCESS && issuer_uri)
+        md_json_sets(issuer_uri, json, MD_KEY_ISSUER_URI, NULL);
     valid.start = md_cert_get_not_before(cert);
     valid.end = md_cert_get_not_after(cert);
     md_json_set_timeperiod(&valid, json, MD_KEY_VALID, NULL);
     md_json_sets(md_cert_get_serial_number(cert, p), json, MD_KEY_SERIAL, NULL);
+    md_json_sets(md_cert_get_serial_number(cert, p), json, MD_KEY_SERIAL, NULL);
     if (APR_SUCCESS != (rv = md_cert_to_sha256_fingerprint(&finger, cert, p))) goto leave;
     md_json_sets(finger, json, MD_KEY_SHA256_FINGERPRINT, NULL);
 
@@ -111,9 +120,14 @@ static apr_status_t status_get_cert_json
     md_json_t *certj, *jobj;
     md_timeperiod_t ocsp_valid;
     md_ocsp_cert_stat_t cert_stat;
+    const char *ari_cert_id;
     apr_status_t rv;
 
     if (APR_SUCCESS != (rv = status_get_cert_json(&certj, cert, p))) goto leave;
+
+    if (APR_SUCCESS == md_cert_get_ari_cert_id(&ari_cert_id, cert, p))
+        md_json_sets(ari_cert_id, certj, MD_KEY_ARI_CERT_ID, NULL);
+
     if (md->stapling && ocsp) {
         rv = md_ocsp_get_meta(&cert_stat, &ocsp_valid, ocsp, cert, p, md);
         if (APR_SUCCESS == rv) {
@@ -126,6 +140,7 @@ static apr_status_t status_get_cert_json
             md_json_setj(jobj, certj, MD_KEY_OCSP, MD_KEY_RENEWAL, NULL);
         }
     }
+
 leave:
     *pjson = (APR_SUCCESS == rv)? certj : NULL;
     return rv;
@@ -206,7 +221,7 @@ static apr_status_t status_get_md_json(m
                                        md_reg_t *reg, md_ocsp_reg_t *ocsp, 
                                        int with_logs, apr_pool_t *p)
 {
-    md_json_t *mdj, *certsj, *jobj;
+    md_json_t *mdj, *certsj, *jobj = NULL;
     int renew;
     const md_pubcert_t *pubcert;
     const md_cert_t *cert = NULL;
@@ -236,20 +251,28 @@ static apr_status_t status_get_md_json(m
     
     md_json_setb(md->stapling, mdj, MD_KEY_STAPLING, NULL);
     md_json_setb(md->watched, mdj, MD_KEY_WATCHED, NULL);
-    renew = md_reg_should_renew(reg, md, p);
+
+    renew = FALSE;
+    rv = job_loadj(&jobj, MD_SG_STAGING, md->name, reg, with_logs, p);
+    if (rv == APR_SUCCESS)
+        renew = TRUE;
+    else if (APR_STATUS_IS_ENOENT(rv)) {
+        rv = APR_SUCCESS;
+        renew = md_reg_should_renew(reg, md, p);
+    }
+    else
+        goto leave;
+
     if (renew) {
         md_json_setb(renew, mdj, MD_KEY_RENEW, NULL);
-        rv = job_loadj(&jobj, MD_SG_STAGING, md->name, reg, with_logs, p);
-        if (APR_SUCCESS == rv) {
+        if (jobj) {
             if (APR_SUCCESS == get_staging_certs_json(&certsj, md, reg, p)) {
                 md_json_setj(certsj, jobj, MD_KEY_CERT, NULL);
             }
             md_json_setj(jobj, mdj, MD_KEY_RENEWAL, NULL);
         }
-        else if (APR_STATUS_IS_ENOENT(rv)) rv = APR_SUCCESS;
-        else goto leave;
     }
-    
+
 leave:
     if (APR_SUCCESS != rv) {
         md_json_setl(rv, mdj, MD_KEY_ERROR, NULL);
@@ -286,7 +309,8 @@ apr_status_t md_status_get_json(md_json_
 /* drive job persistence */
 
 md_job_t *md_job_make(apr_pool_t *p, md_store_t *store,
-                      md_store_group_t group, const char *name)
+                      md_store_group_t group, const char *name,
+                      apr_time_t min_delay)
 {
     md_job_t *job = apr_pcalloc(p, sizeof(*job));
     job->group = group;
@@ -294,6 +318,7 @@ md_job_t *md_job_make(apr_pool_t *p, md_
     job->store = store;
     job->p = p;
     job->max_log = 128;
+    job->min_delay = min_delay;
     return job;
 }
 
@@ -587,10 +612,16 @@ apr_time_t md_job_delay_on_errors(md_job
         delay = max_delay;
     }
     else if (err_count > 0) {
-        /* back off duration, depending on the errors we encounter in a row */
-        delay = apr_time_from_sec(5 << (err_count - 1));
-        if (delay > max_delay) {
-            delay = max_delay;
+        /* back off duration, depending on the errors we encounter in a row.
+         * As apr_time_t is signed, this might wrap around*/
+       
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 39..70
39 /* certificate status information */
40 
41 static apr_status_t status_get_cert_json(md_json_t **pjson, const md_cert_t *cert, apr_pool_t *p)
42 {
43     char ts[APR_RFC822_DATE_LEN];
44     const char *finger;
45     apr_status_t rv = APR_SUCCESS;
46     md_json_t *json;
47     
48     json = md_json_create(p);
49     apr_rfc822_date(ts, md_cert_get_not_before(cert));
50     md_json_sets(ts, json, MD_KEY_VALID_FROM, NULL);
51     apr_rfc822_date(ts, md_cert_get_not_after(cert));
52     md_json_sets(ts, json, MD_KEY_VALID_UNTIL, NULL);
53     md_json_sets(md_cert_get_serial_number(cert, p), json, MD_KEY_SERIAL, NULL);
54     if (APR_SUCCESS != (rv = md_cert_to_sha256_fingerprint(&finger, cert, p))) goto leave;
55     md_json_sets(finger, json, MD_KEY_SHA256_FINGERPRINT, NULL);
56 
57 #if MD_STATUS_WITH_SCTS
58     do {
59         apr_array_header_t *scts;
60         const char *hex;
61         const md_sct *sct;
62         md_json_t *sctj;
63         int i;
64         
65         scts = apr_array_make(p, 5, sizeof(const md_sct*));
66         if (APR_SUCCESS == md_cert_get_ct_scts(scts, p, cert)) {
67             for (i = 0; i < scts->nelts; ++i) {
68                 sct = APR_ARRAY_IDX(scts, i, const md_sct*);
69                 sctj = md_json_create(p);
70                 

Focal lines 103..134
103         goto leave;
104     }
105     else if (APR_SUCCESS != rv) {
106         goto leave;
107     }
108     cert = APR_ARRAY_IDX(certs, 0, md_cert_t *);
109     rv = status_get_cert_json(&json, cert, p);
110 leave:
111     *pjson = (APR_SUCCESS == rv)? json : NULL;
112     return rv;
113 }
114 
115 static apr_status_t job_loadj(md_json_t **pjson, const char *name, 
116                               struct md_reg_t *reg, apr_pool_t *p)
117 {
118     md_store_t *store = md_reg_store_get(reg);
119     return md_store_load_json(store, MD_SG_STAGING, name, MD_FN_JOB, pjson, p);
120 }
121 
122 apr_status_t md_status_get_md_json(md_json_t **pjson, const md_t *md, 
123                                    md_reg_t *reg, apr_pool_t *p)
124 {
125     md_json_t *mdj, *jobj, *certj;
126     int renew;
127     const md_pubcert_t *pubcert;
128     const md_cert_t *cert;
129     apr_status_t rv = APR_SUCCESS;
130 
131     mdj = md_to_json(md, p);
132     if (APR_SUCCESS == md_reg_get_pubcert(&pubcert, reg, md, p)) {
133         cert = APR_ARRAY_IDX(pubcert->certs, 0, const md_cert_t*);
134         if (APR_SUCCESS != (rv = status_get_cert_json(&certj, cert, p))) goto leave;

Focal lines 118..149
118     md_store_t *store = md_reg_store_get(reg);
119     return md_store_load_json(store, MD_SG_STAGING, name, MD_FN_JOB, pjson, p);
120 }
121 
122 apr_status_t md_status_get_md_json(md_json_t **pjson, const md_t *md, 
123                                    md_reg_t *reg, apr_pool_t *p)
124 {
125     md_json_t *mdj, *jobj, *certj;
126     int renew;
127     const md_pubcert_t *pubcert;
128     const md_cert_t *cert;
129     apr_status_t rv = APR_SUCCESS;
130 
131     mdj = md_to_json(md, p);
132     if (APR_SUCCESS == md_reg_get_pubcert(&pubcert, reg, md, p)) {
133         cert = APR_ARRAY_IDX(pubcert->certs, 0, const md_cert_t*);
134         if (APR_SUCCESS != (rv = status_get_cert_json(&certj, cert, p))) goto leave;
135         md_json_setj(certj, mdj, MD_KEY_CERT, NULL);
136     }
137     
138     renew = md_reg_should_renew(reg, md, p);
139     md_json_setb(renew, mdj, MD_KEY_RENEW, NULL);
140     if (renew) {
141         rv = job_loadj(&jobj, md->name, reg, p);
142         if (APR_SUCCESS == rv) {
143             rv = get_staging_cert_json(&certj, p, reg, md);
144             if (APR_SUCCESS != rv) goto leave;
145             if (certj) md_json_setj(certj, jobj, MD_KEY_CERT, NULL);
146             md_json_setj(jobj, mdj, MD_KEY_RENEWAL, NULL);
147         }
148         else if (APR_STATUS_IS_ENOENT(rv)) rv = APR_SUCCESS;
149         else goto leave;
~~~

### modules/md/md_status.h

~~~diff
--- a/modules/md/md_status.h
+++ b/modules/md/md_status.h
@@ -68,6 +68,7 @@ struct md_job_t {
     apr_size_t max_log;    /* max number of log entries, new ones replace oldest */
     int dirty;
     struct md_result_t *observing;
+    apr_time_t min_delay;  /* smallest delay a repeated attempt should have */
 };
 
 /**
@@ -75,7 +76,8 @@ struct md_job_t {
  * Job load/save will work using the name.
  */
 md_job_t *md_job_make(apr_pool_t *p, md_store_t *store, 
-                      md_store_group_t group, const char *name);
+                      md_store_group_t group, const char *name,
+                      apr_time_t min_delay);
 
 void md_job_set_group(md_job_t *job, md_store_group_t group);
 

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 60..91
60  * on the MD_SG_STAGING for the name.
61  */
62 md_job_t *md_job_make(apr_pool_t *p, const char *name);
63 
64 /**
65  * Update the job from storage in <group>/job->name.
66  */
67 apr_status_t md_job_load(md_job_t *job, struct md_reg_t *reg, 
68                          md_store_group_t group, apr_pool_t *p);
69 
70 /**
71  * Update storage from job in <group>/job->name.
72  */
73 apr_status_t md_job_save(md_job_t *job, struct md_reg_t *reg, 
74                          md_store_group_t group, struct md_result_t *result, 
75                          apr_pool_t *p);
76 
77 /**
78  * Append to the job's log. Timestamp is automatically added.
79  * @param type          type of log entry
80  * @param status        status of entry (maybe NULL)
81  * @param detail        description of what happened
82  */
83 void md_job_log_append(md_job_t *job, const char *type, 
84                        const char *status, const char *detail);
85 
86 /**
87  * Retrieve the lastest log entry of a certain type.
88  */
89 md_json_t *md_job_log_get_latest(md_job_t *job, const char *type);
90 
91 /**

Focal lines 67..97
67 apr_status_t md_job_load(md_job_t *job, struct md_reg_t *reg, 
68                          md_store_group_t group, apr_pool_t *p);
69 
70 /**
71  * Update storage from job in <group>/job->name.
72  */
73 apr_status_t md_job_save(md_job_t *job, struct md_reg_t *reg, 
74                          md_store_group_t group, struct md_result_t *result, 
75                          apr_pool_t *p);
76 
77 /**
78  * Append to the job's log. Timestamp is automatically added.
79  * @param type          type of log entry
80  * @param status        status of entry (maybe NULL)
81  * @param detail        description of what happened
82  */
83 void md_job_log_append(md_job_t *job, const char *type, 
84                        const char *status, const char *detail);
85 
86 /**
87  * Retrieve the lastest log entry of a certain type.
88  */
89 md_json_t *md_job_log_get_latest(md_job_t *job, const char *type);
90 
91 /**
92  * Get the time the latest log entry of the given type happened, or 0 if
93  * none is found.
94  */
95 apr_time_t md_job_log_get_time_of_latest(md_job_t *job, const char *type);
96 
97 #endif /* md_status_h */
~~~

### modules/md/md_store.c

~~~diff
--- a/modules/md/md_store.c
+++ b/modules/md/md_store.c
@@ -260,7 +260,7 @@ static const char *pk_filename(const cha
     /* We also run on various filesystems with difference upper/lower preserve matching
      * rules. Normalize the names we use, since private key specifications are basically
      * user input. */
-    s = (keyname && apr_strnatcasecmp("rsa", keyname))?
+    s = (keyname && apr_cstr_casecmp("rsa", keyname))?
         apr_pstrcat(p, base, ".", keyname, ".pem", NULL)
         : apr_pstrcat(p, base, ".pem", NULL);
     for (t = s; *t; t++ )
@@ -374,3 +374,12 @@ apr_status_t md_store_md_iter(md_store_m
     return md_store_iter(insp_md, &ctx, store, p, group, pattern, MD_FN_MD, MD_SV_JSON);
 }
 
+apr_status_t md_store_lock_global(md_store_t *store, apr_pool_t *p, apr_time_t max_wait)
+{
+    return store->lock_global(store, p, max_wait);
+}
+
+void md_store_unlock_global(md_store_t *store, apr_pool_t *p)
+{
+    store->unlock_global(store, p);
+}

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 252..283
252 apr_status_t md_pubcert_load(md_store_t *store, md_store_group_t group, const char *name, 
253                              struct apr_array_header_t **ppubcert, apr_pool_t *p)
254 {
255     return md_store_load(store, group, name, MD_FN_PUBCERT, MD_SV_CHAIN, (void**)ppubcert, p);
256 }
257 
258 apr_status_t md_pubcert_save(md_store_t *store, apr_pool_t *p, 
259                              md_store_group_t group, const char *name, 
260                              struct apr_array_header_t *pubcert, int create)
261 {
262     return md_store_save(store, p, group, name, MD_FN_PUBCERT, MD_SV_CHAIN, pubcert, create);
263 }
264 
265 typedef struct {
266     md_store_t *store;
267     md_store_group_t group;
268     const char *pattern;
269     const char *aspect;
270     md_store_md_inspect *inspect;
271     void *baton;
272 } inspect_md_ctx;
273 
274 static int insp_md(void *baton, const char *name, const char *aspect, 
275                    md_store_vtype_t vtype, void *value, apr_pool_t *ptemp)
276 {
277     inspect_md_ctx *ctx = baton;
278     
279     if (!strcmp(MD_FN_MD, aspect) && vtype == MD_SV_JSON) {
280         md_t *md = md_from_json(value, ptemp);
281         md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, ptemp, "inspecting md at: %s", name);
282         return ctx->inspect(ctx->baton, ctx->store, md, ptemp);
283     }

Focal lines 300..299

~~~

### modules/md/md_store.h

~~~diff
--- a/modules/md/md_store.h
+++ b/modules/md/md_store.h
@@ -204,7 +204,23 @@ apr_status_t md_store_iter_names(md_stor
 apr_time_t md_store_get_modified(md_store_t *store, md_store_group_t group,  
                                  const char *name, const char *aspect, apr_pool_t *p);
 
+/**
+ * Acquire a cooperative, global lock on store modifications.
 
+ * This will only prevent other children/processes/cluster nodes from
+ * doing the same and does not protect individual store functions from
+ * being called without it.
+ * @param store the store
+ * @param p memory pool to use
+ * @param max_wait maximum time to wait in order to acquire
+ * @return APR_SUCCESS when lock was obtained
+ */
+apr_status_t md_store_lock_global(md_store_t *store, apr_pool_t *p, apr_time_t max_wait);
+
+/**
+ * Realease the global store lock. Will do nothing if there is no lock.
+ */
+void md_store_unlock_global(md_store_t *store, apr_pool_t *p);
 
 /**************************************************************************************************/
 /* Storage handling utils */
@@ -303,6 +319,8 @@ typedef apr_time_t md_store_get_modified
 typedef apr_status_t md_store_remove_nms_cb(md_store_t *store, apr_pool_t *p, 
                                             apr_time_t modified, md_store_group_t group, 
                                             const char *name, const char *aspect);
+typedef apr_status_t md_store_lock_global_cb(md_store_t *store, apr_pool_t *p, apr_time_t max_wait);
+typedef void md_store_unlock_global_cb(md_store_t *store, apr_pool_t *p);
 
 struct md_store_t {
     md_store_save_cb *save;
@@ -317,6 +335,8 @@ struct md_store_t {
     md_store_is_newer_cb *is_newer;
     md_store_get_modified_cb *get_modified;
     md_store_remove_nms_cb *remove_nms;
+    md_store_lock_global_cb *lock_global;
+    md_store_unlock_global_cb *unlock_global;
 };
 
 

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 158..157


Focal lines 158..157


Focal lines 158..157

~~~

### modules/md/md_store_fs.c

~~~diff
--- a/modules/md/md_store_fs.c
+++ b/modules/md/md_store_fs.c
@@ -39,6 +39,7 @@
 /* file system based implementation of md_store_t */
 
 #define MD_STORE_VERSION        3
+#define MD_FS_LOCK_NAME         "store.lock"
 
 typedef struct {
     apr_fileperms_t dir;
@@ -60,6 +61,8 @@ struct md_store_fs_t {
     
     int port_80;
     int port_443;
+
+    apr_file_t *global_lock;
 };
 
 #define FS_STORE(store)     (md_store_fs_t*)(((char*)store)-offsetof(md_store_fs_t, s))
@@ -101,6 +104,9 @@ static int fs_is_newer(md_store_t *store
 static apr_time_t fs_get_modified(md_store_t *store, md_store_group_t group,  
                                   const char *name, const char *aspect, apr_pool_t *p);
 
+static apr_status_t fs_lock_global(md_store_t *store, apr_pool_t *p, apr_time_t max_wait);
+static void fs_unlock_global(md_store_t *store, apr_pool_t *p);
+
 static apr_status_t init_store_file(md_store_fs_t *s_fs, const char *fname, 
                                     apr_pool_t *p, apr_pool_t *ptemp)
 {
@@ -240,8 +246,8 @@ static apr_status_t read_store_file(md_s
             if (APR_SUCCESS == rv) {
                 md_json_setn(MD_STORE_VERSION, json, MD_KEY_STORE, MD_KEY_VERSION, NULL);
                 rv = md_json_freplace(json, ptemp, MD_JSON_FMT_INDENT, fname, MD_FPROT_F_UONLY);
-           }
-           md_log_perror(MD_LOG_MARK, MD_LOG_INFO, rv, p, "migrated store");
+            }
+            md_log_perror(MD_LOG_MARK, MD_LOG_INFO, rv, p, "migrated store");
         } 
     }
     return rv;
@@ -269,6 +275,15 @@ static apr_status_t setup_store_file(voi
 read:
     if (MD_OK(md_util_is_file(fname, ptemp))) {
         rv = read_store_file(s_fs, fname, p, ptemp);
+        if (rv != APR_SUCCESS) {
+            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p,
+            "The central store file md/md_store.json seems to exist, but "
+            "its content are not readable as JSON. Either it got somehow corrupted "
+            "or the store directory was configured for a location with a foreign "
+            "md_store.json file. Either way, it is unclear how to proceeed. "
+            "You should either restore the correct file/location or clean the directory "
+            "so it gets initialized again.");
+        }
     }
     else if (APR_STATUS_IS_ENOENT(rv)
         && APR_STATUS_IS_EEXIST(rv = init_store_file(s_fs, fname, p, ptemp))) {
@@ -296,7 +311,9 @@ apr_status_t md_store_fs_init(md_store_t
     s_fs->s.is_newer = fs_is_newer;
     s_fs->s.get_modified = fs_get_modified;
     s_fs->s.remove_nms = fs_remove_nms;
-    
+    s_fs->s.lock_global = fs_lock_global;
+    s_fs->s.unlock_global = fs_unlock_global;
+
     /* by default, everything is only readable by the current user */ 
     s_fs->def_perms.dir = MD_FPROT_D_UONLY;
     s_fs->def_perms.file = MD_FPROT_F_UONLY;
@@ -521,7 +538,8 @@ static apr_status_t mk_group_dir(const c
     }
 cleanup:
     if (APR_SUCCESS != rv) {
-        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "mk_group_dir %d %s", group, name);
+        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "mk_group_dir %d %s",
+                      group, (*pdir? *pdir : (name? name : "(null)")));
     }
     return rv;
 }
@@ -1093,3 +1111,67 @@ static apr_status_t fs_rename(md_store_t
     md_store_fs_t *s_fs = FS_STORE(store);
     return md_util_pool_vdo(pfs_rename, s_fs, p, group, from, to, NULL);
 }
+
+static apr_status_t fs_lock_global(md_store_t *store, apr_pool_t *p, apr_time_t max_wait)
+{
+    md_store_fs_t *s_fs = FS_STORE(store);
+    apr_status_t rv;
+    const char *lpath;
+    apr_time_t end;
+
+    if (s_fs->global_lock) {
+        rv = APR_EEXIST;
+        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "already locked globally");
+        goto cleanup;
+    }
+
+    rv = md_util_path_merge(&lpath, p, s_fs->base, MD_FS_LOCK_NAME, NULL);
+    if (APR_SUCCESS != rv) goto cleanup;
+    end = apr_time_now() + max_wait;
+
+    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, p,
+                  "acquire global lock: %s", lpath);
+    while (apr_time_now() < end) {
+        rv = apr_file_open(&s_fs->global_lock, lpath,
+                           (APR_FOPEN_WRITE|APR_FOPEN_CREATE),
+                           MD_FPROT_F_UALL_GREAD, p);
+        if (APR_SUCCESS != rv) {
+            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, p,
+                          "unable to create/open lock file: %s",
+                          lpath);
+            goto next_try;
+        }
+        rv 
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 31..62
31 #include "md_json.h"
32 #include "md_log.h"
33 #include "md_store.h"
34 #include "md_store_fs.h"
35 #include "md_util.h"
36 #include "md_version.h"
37 
38 /**************************************************************************************************/
39 /* file system based implementation of md_store_t */
40 
41 #define MD_STORE_VERSION        3
42 
43 typedef struct {
44     apr_fileperms_t dir;
45     apr_fileperms_t file;
46 } perms_t;
47 
48 typedef struct md_store_fs_t md_store_fs_t;
49 struct md_store_fs_t {
50     md_store_t s;
51     
52     const char *base;       /* base directory of store */
53     perms_t def_perms;
54     perms_t group_perms[MD_SG_COUNT];
55     md_store_fs_cb *event_cb;
56     void *event_baton;
57     
58     const unsigned char *key;
59     apr_size_t key_len;
60     int plain_pkey[MD_SG_COUNT];
61     
62     int port_80;

Focal lines 52..83
52     const char *base;       /* base directory of store */
53     perms_t def_perms;
54     perms_t group_perms[MD_SG_COUNT];
55     md_store_fs_cb *event_cb;
56     void *event_baton;
57     
58     const unsigned char *key;
59     apr_size_t key_len;
60     int plain_pkey[MD_SG_COUNT];
61     
62     int port_80;
63     int port_443;
64 };
65 
66 #define FS_STORE(store)     (md_store_fs_t*)(((char*)store)-offsetof(md_store_fs_t, s))
67 #define FS_STORE_JSON       "md_store.json"
68 #define FS_STORE_KLEN       48
69 
70 static apr_status_t fs_load(md_store_t *store, md_store_group_t group, 
71                             const char *name, const char *aspect,  
72                             md_store_vtype_t vtype, void **pvalue, apr_pool_t *p);
73 static apr_status_t fs_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
74                             const char *name, const char *aspect,  
75                             md_store_vtype_t vtype, void *value, int create);
76 static apr_status_t fs_remove(md_store_t *store, md_store_group_t group, 
77                               const char *name, const char *aspect, 
78                               apr_pool_t *p, int force);
79 static apr_status_t fs_purge(md_store_t *store, apr_pool_t *p, 
80                              md_store_group_t group, const char *name);
81 static apr_status_t fs_move(md_store_t *store, apr_pool_t *p, 
82                             md_store_group_t from, md_store_group_t to, 
83                             const char *name, int archive);

Focal lines 93..124
93                                  apr_pool_t *p);
94 static int fs_is_newer(md_store_t *store, md_store_group_t group1, md_store_group_t group2,  
95                        const char *name, const char *aspect, apr_pool_t *p);
96 
97 static apr_status_t init_store_file(md_store_fs_t *s_fs, const char *fname, 
98                                     apr_pool_t *p, apr_pool_t *ptemp)
99 {
100     md_json_t *json = md_json_create(p);
101     const char *key64;
102     unsigned char *key;
103     apr_status_t rv;
104     
105     md_json_setn(MD_STORE_VERSION, json, MD_KEY_STORE, MD_KEY_VERSION, NULL);
106 
107     s_fs->key_len = FS_STORE_KLEN;
108     s_fs->key = key = apr_pcalloc(p, FS_STORE_KLEN);
109     if (APR_SUCCESS != (rv = md_rand_bytes(key, s_fs->key_len, p))) {
110         return rv;
111     }
112         
113     key64 = md_util_base64url_encode((char *)key, s_fs->key_len, ptemp);
114     md_json_sets(key64, json, MD_KEY_KEY, NULL);
115     rv = md_json_fcreatex(json, ptemp, MD_JSON_FMT_INDENT, fname, MD_FPROT_F_UONLY);
116     memset((char*)key64, 0, strlen(key64));
117 
118     return rv;
119 }
120 
121 static apr_status_t rename_pkey(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
122                                 const char *dir, const char *name, 
123                                 apr_filetype_e ftype)
124 {
~~~

### modules/md/md_time.c

~~~diff
--- a/modules/md/md_time.c
+++ b/modules/md/md_time.c
@@ -323,3 +323,70 @@ md_timeperiod_t md_timeperiod_common(con
     }
     return c;
 }
+
+apr_time_t md_time_parse_rfc3339(const char *s)
+{
+    apr_time_exp_t t;
+    apr_time_t ts;
+    apr_size_t i = 0;
+
+    memset(&t, 0, sizeof(t));
+    if (!apr_isdigit(s[0]) || !apr_isdigit(s[1]) || !apr_isdigit(s[2]) ||
+        !apr_isdigit(s[3]) ||
+        (s[4] != '-') ||
+        !apr_isdigit(s[5]) || !apr_isdigit(s[6]) ||
+        (s[7] != '-') ||
+        !apr_isdigit(s[8]) || !apr_isdigit(s[9]) ||
+        ((s[10] != 'T') && (s[10] != 't')) ||
+        !apr_isdigit(s[11]) || !apr_isdigit(s[12]) ||
+        (s[13] != ':') ||
+        !apr_isdigit(s[14]) || !apr_isdigit(s[15]) ||
+        (s[16] != ':') ||
+        !apr_isdigit(s[17]) || !apr_isdigit(s[18])
+        )
+        return 0;
+    t.tm_year = (s[0] - '0') * 1000;
+    t.tm_year += (s[1] - '0') * 100;
+    t.tm_year += (s[2] - '0') * 10;
+    t.tm_year += (s[3] - '0');
+    t.tm_year -= 1900; /* the apr time 0 point */
+    t.tm_mon = (s[5] - '0') * 10;
+    t.tm_mon += (s[6] - '0') - 1; /* -1 since January is 0 not 1. */
+    t.tm_mday = (s[8] - '0') * 10;
+    t.tm_mday += (s[9] - '0');
+    t.tm_hour = (s[11] - '0') * 10;
+    t.tm_hour += (s[12] - '0');
+    t.tm_min = (s[14] - '0') * 10;
+    t.tm_min += (s[15] - '0');
+    t.tm_sec = (s[17] - '0') * 10;
+    t.tm_sec += (s[18] - '0');
+
+    i = 19;
+    if (s[i] == '.') {
+        for(i += 1; apr_isdigit(s[i]); ++i)
+            ; /* skip for now */
+    }
+
+    if ((s[i] == 'Z') || (s[i] == 'z')) {
+        /* alredy GMT, done */
+        t.tm_gmtoff = 0;
+    }
+    else if (((s[i] == '+') || (s[i] == '-')) &&
+            apr_isdigit(s[i+1]) && apr_isdigit(s[i+2]) &&
+            (s[i+3] == ':') &&
+            apr_isdigit(s[i+4]) && apr_isdigit(s[i+5])) {
+        /* tm_gmtoff is in seconds */
+        t.tm_gmtoff = (s[i+1] - '0') * 10 * (60 * 60);
+        t.tm_gmtoff += (s[i+2] - '0') * (60 * 60);
+        t.tm_gmtoff = (s[i+4] - '0') * 10 * 60;
+        t.tm_gmtoff += (s[i+5] - '0') * 60;
+        if (s[i] == '-')
+            t.tm_gmtoff *= -1;
+    }
+    else
+        return 0;
+
+    if (APR_SUCCESS == apr_time_exp_gmt_get(&ts, &t))
+        return ts;
+    return 0;
+}

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 285..284

~~~

### modules/md/md_time.h

~~~diff
--- a/modules/md/md_time.h
+++ b/modules/md/md_time.h
@@ -74,4 +74,7 @@ const char *md_timeslice_format(const md
 md_timeperiod_t md_timeperiod_slice_before_end(const md_timeperiod_t *period, 
                                                const md_timeslice_t *ts);
 
+/* parse rfc3339 timestamp, return 0 when not valid */
+apr_time_t md_time_parse_rfc3339(const char *s);
+
 #endif /* md_util_h */

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 66..67
66 
67 #endif /* md_util_h */
~~~

### modules/md/md_util.c

~~~diff
--- a/modules/md/md_util.c
+++ b/modules/md/md_util.c
@@ -256,7 +256,7 @@ int md_array_str_index(const apr_array_h
         for (i = start; i < array->nelts; i++) {
             const char *p = APR_ARRAY_IDX(array, i, const char *);
             if ((case_sensitive && !strcmp(p, s))
-                || (!case_sensitive && !apr_strnatcasecmp(p, s))) {
+                || (!case_sensitive && !apr_cstr_casecmp(p, s))) {
                 return i;
             }
         }
@@ -278,7 +278,7 @@ int md_array_str_eq(const struct apr_arr
         s1 = APR_ARRAY_IDX(a1, i, const char *);
         s2 = APR_ARRAY_IDX(a2, i, const char *);
         if ((case_sensitive && strcmp(s1, s2))
-            || (!case_sensitive && apr_strnatcasecmp(s1, s2))) {
+            || (!case_sensitive && apr_cstr_casecmp(s1, s2))) {
             return 0;
         }
     }
@@ -325,7 +325,7 @@ apr_array_header_t *md_array_str_remove(
             const char *s = APR_ARRAY_IDX(src, i, const char *);
             if (!exclude 
                 || (case_sensitive && strcmp(exclude, s))
-                || (!case_sensitive && apr_strnatcasecmp(exclude, s))) {
+                || (!case_sensitive && apr_cstr_casecmp(exclude, s))) {
                 APR_ARRAY_PUSH(dest, const char *) = apr_pstrdup(p, s); 
             }
         }
@@ -398,6 +398,16 @@ apr_status_t md_util_is_file(const char
     return rv;
 }
 
+apr_status_t md_util_is_unix_socket(const char *path, apr_pool_t *pool)
+{
+    apr_finfo_t info;
+    apr_status_t rv = apr_stat(&info, path, APR_FINFO_TYPE, pool);
+    if (rv == APR_SUCCESS) {
+        rv = (info.filetype == APR_SOCK)? APR_SUCCESS : APR_EINVAL;
+    }
+    return rv;
+}
+
 int md_file_exists(const char *fname, apr_pool_t *p)
 {
     return (fname && *fname && APR_SUCCESS == md_util_is_file(fname, p));
@@ -849,10 +859,10 @@ int md_dns_matches(const char *pattern,
 {
     const char *s;
     
-    if (!apr_strnatcasecmp(pattern, domain)) return 1;
+    if (!apr_cstr_casecmp(pattern, domain)) return 1;
     if (pattern[0] == '*' && pattern[1] == '.') {
         s = strchr(domain, '.');
-        if (s && !apr_strnatcasecmp(pattern+1, s)) return 1;
+        if (s && !apr_cstr_casecmp(pattern+1, s)) return 1;
     }
     return 0;
 }
@@ -906,6 +916,19 @@ int md_dns_domains_match(const apr_array
     return 0;
 }
 
+int md_is_wild_match(const apr_array_header_t *domains, const char *name)
+{
+    const char *domain;
+    int i;
+
+    for (i = 0; i < domains->nelts; ++i) {
+        domain = APR_ARRAY_IDX(domains, i, const char*);
+        if (md_dns_matches(domain, name))
+            return (domain[0] == '*' && domain[1] == '.');
+    }
+    return 0;
+}
+
 const char *md_util_schemify(apr_pool_t *p, const char *s, const char *def_scheme)
 {
     const char *cp = s;
@@ -1003,8 +1026,8 @@ apr_status_t md_util_abs_http_uri_check(
             *perr = "missing uri scheme";
             return APR_EINVAL;
         }
-        if (apr_strnatcasecmp("http", uri_parsed.scheme) 
-            && apr_strnatcasecmp("https", uri_parsed.scheme)) {
+        if (apr_cstr_casecmp("http", uri_parsed.scheme) 
+            && apr_cstr_casecmp("https", uri_parsed.scheme)) {
             *perr = "uri scheme must be http or https";
             return APR_EINVAL;
         }
@@ -1058,32 +1081,24 @@ apr_status_t md_util_try(md_util_try_fn
 
 /* execute process ********************************************************************************/
 
-apr_status_t md_util_exec(apr_pool_t *p, const char *cmd, const char * const *argv,
-                          apr_array_header_t *env, int *exit_code)
+apr_status_t md_util_exec(apr_pool_t *p, const char *cmd,
+                          const char * const *argv, int *exit_code)
 {
     apr_status_t rv;
     apr_procattr_t *procattr;
     apr_proc_t *proc;
     apr_exit_why_e ewhy;
-    const char * const *envp = NULL;
     char buffer[1024];
     
     *exit_code = 0;
     if (!(proc = apr_pcalloc(p, sizeof(*proc)))) {
         return APR_ENOMEM;
     }
-    if (env && env->nelts > 0) {
-        apr_array_header_t *nenv;
-        
-        nenv = apr_array_copy(p, env);
-        APR_ARRAY_PUSH(nenv, const char *) = NULL;
-        envp = (const char * const *)nenv->elts;
-    }
     if (   APR_SUCCESS == (rv = apr_procattr_create(&procattr, p))
         && APR_SUCCESS == (rv = apr_procattr_io_set(procattr, APR_NO_FILE, 
                                                     APR_NO_PIPE, APR_FULL_BLOCK))
-        && APR_
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 248..279
248         return errno;
249     }
250 
251     return APR_SUCCESS;
252 }
253 
254 apr_status_t md_util_fcreatex(apr_file_t **pf, const char *fn, 
255                               apr_fileperms_t perms, apr_pool_t *p)
256 {
257     apr_status_t rv;
258     rv = apr_file_open(pf, fn, (APR_FOPEN_WRITE|APR_FOPEN_CREATE|APR_FOPEN_EXCL),
259                        perms, p);
260     if (APR_SUCCESS == rv) {
261         /* See <https://github.com/icing/mod_md/issues/117>
262          * Some people set umask 007 to deny all world read/writability to files
263          * created by apache. While this is a noble effort, we need the store files
264          * to have the permissions as specified. */
265         rv = apr_file_perms_set(fn, perms);
266         if (APR_STATUS_IS_ENOTIMPL(rv)) {
267             rv = APR_SUCCESS;
268         }
269     }
270     return rv;
271 }
272 
273 apr_status_t md_util_is_dir(const char *path, apr_pool_t *pool)
274 {
275     apr_finfo_t info;
276     apr_status_t rv = apr_stat(&info, path, APR_FINFO_TYPE, pool);
277     if (rv == APR_SUCCESS) {
278         rv = (info.filetype == APR_DIR)? APR_SUCCESS : APR_EINVAL;
279     }

Focal lines 270..301
270     return rv;
271 }
272 
273 apr_status_t md_util_is_dir(const char *path, apr_pool_t *pool)
274 {
275     apr_finfo_t info;
276     apr_status_t rv = apr_stat(&info, path, APR_FINFO_TYPE, pool);
277     if (rv == APR_SUCCESS) {
278         rv = (info.filetype == APR_DIR)? APR_SUCCESS : APR_EINVAL;
279     }
280     return rv;
281 }
282 
283 apr_status_t md_util_is_file(const char *path, apr_pool_t *pool)
284 {
285     apr_finfo_t info;
286     apr_status_t rv = apr_stat(&info, path, APR_FINFO_TYPE, pool);
287     if (rv == APR_SUCCESS) {
288         rv = (info.filetype == APR_REG)? APR_SUCCESS : APR_EINVAL;
289     }
290     return rv;
291 }
292 
293 int md_file_exists(const char *fname, apr_pool_t *p)
294 {
295     return (fname && *fname && APR_SUCCESS == md_util_is_file(fname, p));
296 }
297 
298 apr_status_t md_util_path_merge(const char **ppath, apr_pool_t *p, ...)
299 {
300     const char *segment, *path;
301     va_list ap;

Focal lines 317..348
317 {
318     apr_status_t rv = APR_EEXIST;
319     apr_file_t *f;
320     const char *tmp;
321     int i, max;
322     
323     tmp = apr_psprintf(p, "%s.tmp", fpath);
324     i = 0; max = 20;
325 creat:
326     while (i < max && APR_EEXIST == (rv = md_util_fcreatex(&f, tmp, perms, p))) {
327         ++i;
328         apr_sleep(apr_time_msec(50));
329     } 
330     if (APR_EEXIST == rv 
331         && APR_SUCCESS == (rv = apr_file_remove(tmp, p))
332         && max <= 20) {
333         max *= 2;
334         goto creat;
335     }
336     
337     if (APR_SUCCESS == rv) {
338         rv = write_cb(baton, f, p);
339         apr_file_close(f);
340         
341         if (APR_SUCCESS == rv) {
342             rv = apr_file_rename(tmp, fpath, p);
343             if (APR_SUCCESS != rv) {
344                 apr_file_remove(tmp, p);
345             }
346         }
347     }
348     return rv;
~~~

### modules/md/md_util.h

~~~diff
--- a/modules/md/md_util.h
+++ b/modules/md/md_util.h
@@ -20,6 +20,16 @@
 #include <stdio.h>
 #include <apr_file_io.h>
 
+#include <apr_version.h>
+
+#if APR_VERSION_AT_LEAST(1,6,0)
+#include <apr_cstr.h>
+#else
+/* Define a (poor) backwards-compatibility entry point for
+ * apr_cstr_casecmp() from APR 1.6. */
+#define apr_cstr_casecmp apr_natcasecmp
+#endif
+
 struct apr_array_header_t;
 struct apr_table_t;
 
@@ -133,7 +143,7 @@ int md_array_str_add_missing(struct apr_
 /* process execution */
 
 apr_status_t md_util_exec(apr_pool_t *p, const char *cmd, const char * const *argv,
-                          struct apr_array_header_t *env, int *exit_code);
+                          int *exit_code);
 
 /**************************************************************************************************/
 /* dns name check */
@@ -174,6 +184,11 @@ struct apr_array_header_t *md_dns_make_m
  */
 int md_dns_domains_match(const apr_array_header_t *domains, const char *name);
 
+/**
+ * @return != 0 iff `name` is matched by a wildcard pattern in `domains`
+ */
+int md_is_wild_match(const apr_array_header_t *domains, const char *name);
+
 /**************************************************************************************************/
 /* file system related */
 
@@ -189,6 +204,7 @@ apr_status_t md_util_path_merge(const ch
 
 apr_status_t md_util_is_dir(const char *path, apr_pool_t *pool);
 apr_status_t md_util_is_file(const char *path, apr_pool_t *pool);
+apr_status_t md_util_is_unix_socket(const char *path, apr_pool_t *pool);
 int md_file_exists(const char *fname, apr_pool_t *p);
 
 typedef apr_status_t md_util_file_cb(void *baton, struct apr_file_t *f, apr_pool_t *p);

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 12..43
12  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
13  * See the License for the specific language governing permissions and
14  * limitations under the License.
15  */
16 
17 #ifndef mod_md_md_util_h
18 #define mod_md_md_util_h
19 
20 #include <stdio.h>
21 #include <apr_file_io.h>
22 
23 struct apr_array_header_t;
24 struct apr_table_t;
25 
26 /**************************************************************************************************/
27 /* pool utils */
28 
29 typedef apr_status_t md_util_action(void *baton, apr_pool_t *p, apr_pool_t *ptemp);
30 typedef apr_status_t md_util_vaction(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap);
31 
32 apr_status_t md_util_pool_do(md_util_action *cb, void *baton, apr_pool_t *p); 
33 apr_status_t md_util_pool_vdo(md_util_vaction *cb, void *baton, apr_pool_t *p, ...); 
34 
35 /**************************************************************************************************/
36 /* data chunks */
37 
38 typedef struct md_data md_data;
39 struct md_data {
40     const char *data;
41     apr_size_t len;
42 };
43 

Focal lines 125..156
125 /**************************************************************************************************/
126 /* file system related */
127 
128 struct apr_file_t;
129 struct apr_finfo_t;
130 
131 apr_status_t md_util_fopen(FILE **pf, const char *fn, const char *mode);
132 
133 apr_status_t md_util_fcreatex(struct apr_file_t **pf, const char *fn, 
134                               apr_fileperms_t perms, apr_pool_t *p);
135 
136 apr_status_t md_util_path_merge(const char **ppath, apr_pool_t *p, ...);
137 
138 apr_status_t md_util_is_dir(const char *path, apr_pool_t *pool);
139 apr_status_t md_util_is_file(const char *path, apr_pool_t *pool);
140 int md_file_exists(const char *fname, apr_pool_t *p);
141 
142 typedef apr_status_t md_util_file_cb(void *baton, struct apr_file_t *f, apr_pool_t *p);
143 
144 apr_status_t md_util_freplace(const char *fpath, apr_fileperms_t perms, apr_pool_t *p, 
145                               md_util_file_cb *write, void *baton);
146 
147 /** 
148  * Remove a file/directory and all files/directories contain up to max_level. If max_level == 0,
149  * only an empty directory or a file can be removed.
150  */
151 apr_status_t md_util_rm_recursive(const char *fpath, apr_pool_t *p, int max_level);
152 
153 typedef apr_status_t md_util_fdo_cb(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
154                                          const char *dir, const char *name, 
155                                          apr_filetype_e ftype);
156                                          

Focal lines 166..197
166 apr_status_t md_util_ftree_remove(const char *path, apr_pool_t *p);
167 
168 apr_status_t md_text_fread8k(const char **ptext, apr_pool_t *p, const char *fpath);
169 apr_status_t md_text_fcreatex(const char *fpath, apr_fileperms_t 
170                               perms, apr_pool_t *p, const char *text);
171 apr_status_t md_text_freplace(const char *fpath, apr_fileperms_t perms, 
172                               apr_pool_t *p, const char *text); 
173 
174 /**************************************************************************************************/
175 /* base64 url encodings */
176 const char *md_util_base64url_encode(const char *data, 
177                                      apr_size_t len, apr_pool_t *pool);
178 apr_size_t md_util_base64url_decode(const char **decoded, const char *encoded, 
179                                     apr_pool_t *pool);
180 
181 /**************************************************************************************************/
182 /* http/url related */
183 const char *md_util_schemify(apr_pool_t *p, const char *s, const char *def_scheme);
184 
185 apr_status_t md_util_abs_uri_check(apr_pool_t *p, const char *s, const char **perr);
186 apr_status_t md_util_abs_http_uri_check(apr_pool_t *p, const char *uri, const char **perr);
187 
188 const char *md_link_find_relation(const struct apr_table_t *headers, 
189                                   apr_pool_t *pool, const char *relation);
190 
191 /**************************************************************************************************/
192 /* retry logic */
193 
194 typedef apr_status_t md_util_try_fn(void *baton, int i);
195 
196 apr_status_t md_util_try(md_util_try_fn *fn, void *baton, int ignore_errs,  
197                          apr_interval_time_t timeout, apr_interval_time_t start_delay, 
~~~

### modules/md/md_version.h

~~~diff
--- a/modules/md/md_version.h
+++ b/modules/md/md_version.h
@@ -27,7 +27,7 @@
  * @macro
  * Version number of the md module as c string
  */
-#define MOD_MD_VERSION "2.4.10"
+#define MOD_MD_VERSION "2.6.6"
 
 /**
  * @macro
@@ -35,8 +35,8 @@
  * release. This is a 24 bit number with 8 bits for major number, 8 bits
  * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
  */
-#define MOD_MD_VERSION_NUM 0x02040a
+#define MOD_MD_VERSION_NUM 0x020606
 
-#define MD_ACME_DEF_URL    "https://acme-v02.api.letsencrypt.org/directory"
+#define MD_ACME_DEF_URL         "https://acme-v02.api.letsencrypt.org/directory"
 
 #endif /* mod_md_md_version_h */

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 19..42
19 
20 #undef PACKAGE_VERSION
21 #undef PACKAGE_TARNAME
22 #undef PACKAGE_STRING
23 #undef PACKAGE_NAME
24 #undef PACKAGE_BUGREPORT
25 
26 /**
27  * @macro
28  * Version number of the md module as c string
29  */
30 #define MOD_MD_VERSION "2.0.10"
31 
32 /**
33  * @macro
34  * Numerical representation of the version number of the md module
35  * release. This is a 24 bit number with 8 bits for major number, 8 bits
36  * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
37  */
38 #define MOD_MD_VERSION_NUM 0x02000a
39 
40 #define MD_ACME_DEF_URL    "https://acme-v02.api.letsencrypt.org/directory"
41 
42 #endif /* mod_md_md_version_h */

Focal lines 27..42
27  * @macro
28  * Version number of the md module as c string
29  */
30 #define MOD_MD_VERSION "2.0.10"
31 
32 /**
33  * @macro
34  * Numerical representation of the version number of the md module
35  * release. This is a 24 bit number with 8 bits for major number, 8 bits
36  * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
37  */
38 #define MOD_MD_VERSION_NUM 0x02000a
39 
40 #define MD_ACME_DEF_URL    "https://acme-v02.api.letsencrypt.org/directory"
41 
42 #endif /* mod_md_md_version_h */
~~~

### modules/md/mod_md.c

~~~diff
--- a/modules/md/mod_md.c
+++ b/modules/md/mod_md.c
@@ -98,7 +98,7 @@ static void log_print(const char *file,
         buffer[LOG_BUF_LEN-1] = '\0';
 
         if (log_server) {
-            ap_log_error(file, line, APLOG_MODULE_INDEX, (int)level, rv, log_server, "%s",buffer);
+            ap_log_error(file, line, APLOG_MODULE_INDEX, (int)level, rv, log_server, "%s", buffer);
         }
         else {
             ap_log_perror(file, line, APLOG_MODULE_INDEX, (int)level, rv, p, "%s", buffer);
@@ -183,7 +183,7 @@ static apr_status_t notify(md_job_t *job
         if (mc->notify_cmd) {
             cmdline = apr_psprintf(p, "%s %s", mc->notify_cmd, job->mdomain);
             apr_tokenize_to_argv(cmdline, (char***)&argv, p);
-            rv = md_util_exec(p, argv[0], argv, NULL, &exit_code);
+            rv = md_util_exec(p, argv[0], argv, &exit_code);
 
             if (APR_SUCCESS == rv && exit_code) rv = APR_EGENERAL;
             if (APR_SUCCESS != rv) {
@@ -202,7 +202,7 @@ static apr_status_t notify(md_job_t *job
     if (mc->message_cmd) {
         cmdline = apr_psprintf(p, "%s %s %s", mc->message_cmd, reason, job->mdomain);
         apr_tokenize_to_argv(cmdline, (char***)&argv, p);
-        rv = md_util_exec(p, argv[0], argv, NULL, &exit_code);
+        rv = md_util_exec(p, argv[0], argv, &exit_code);
 
         if (APR_SUCCESS == rv && exit_code) rv = APR_EGENERAL;
         if (APR_SUCCESS != rv) {
@@ -313,8 +313,8 @@ static void merge_srv_config(md_t *md, m
         md->sc = base_sc;
     }
 
-    if (!md->ca_url) {
-        md->ca_url = md_config_gets(md->sc, MD_CONFIG_CA_URL);
+    if (!md->ca_urls && md->sc->ca_urls) {
+        md->ca_urls = apr_array_copy(p, md->sc->ca_urls);
     }
     if (!md->ca_proto) {
         md->ca_proto = md_config_gets(md->sc, MD_CONFIG_CA_PROTO);
@@ -331,7 +331,8 @@ static void merge_srv_config(md_t *md, m
         APR_ARRAY_PUSH(md->contacts, const char *) =
         md_util_schemify(p, contact, "mailto");
     }
-    else if( md->sc->s->server_admin && strcmp(DEFAULT_ADMIN, md->sc->s->server_admin)) {
+    else if (md->sc->s->server_admin &&
+             strcmp(DEFAULT_ADMIN, md->sc->s->server_admin)) {
         apr_array_clear(md->contacts);
         APR_ARRAY_PUSH(md->contacts, const char *) =
         md_util_schemify(p, md->sc->s->server_admin, "mailto");
@@ -363,6 +364,15 @@ static void merge_srv_config(md_t *md, m
     if (md->stapling < 0) {
         md->stapling = md_config_geti(md->sc, MD_CONFIG_STAPLING);
     }
+    if (!md->profile) {
+        md->profile = md_config_gets(md->sc, MD_CONFIG_CA_PROFILE);
+    }
+    if (md->profile_mandatory < 0) {
+        md->profile_mandatory = md_config_geti(md->sc, MD_CONFIG_CA_PROFILE_MANDATORY);
+    }
+    if (md->ari_renewals < 0) {
+        md->ari_renewals = md_config_geti(md->sc, MD_CONFIG_ARI_RENEWALS);
+    }
 }
 
 static apr_status_t check_coverage(md_t *md, const char *domain, server_rec *s,
@@ -377,12 +387,12 @@ static apr_status_t check_coverage(md_t
         return APR_SUCCESS;
     }
     else {
-        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(10040)
+        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10040)
                      "Virtual Host %s:%d matches Managed Domain '%s', but the "
                      "name/alias %s itself is not managed. A requested MD certificate "
                      "will not match ServerName.",
                      s->server_hostname, s->port, md->name, domain);
-        return APR_EINVAL;
+        return APR_SUCCESS;
     }
 }
 
@@ -586,18 +596,30 @@ static apr_status_t link_md_to_servers(m
         for (i = 0; i < md->domains->nelts; ++i) {
             domain = APR_ARRAY_IDX(md->domains, i, const char*);
 
-            if (ap_matches_request_vhost(&r, domain, s->port)
-                || (md_dns_is_wildcard(p, domain) && md_dns_matches(domain, s->server_hostname))) {
+            if ((mc->match_mode == MD_MATCH_ALL &&
+                 ap_matches_request_vhost(&r, domain, s->port))
+                || (((mc->match_mode == MD_MATCH_SERVERNAMES) || md_dns_is_wildcard(p, domain)) &&
+                    md_dns_matches(domain, s->server_hostname))) {
                 /* Create a unique md_srv_conf_t record for this server, if there is none yet */
                 sc = md_config_get_unique(s, p);
                 if (!sc->assigned) sc->assigned = apr_array_make(p, 2, sizeof(md_t*));
-
+                if (sc->assigned->nelts == 1 && mc->match_mode == MD_MATCH_S
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 90..121
90         char buffer[LOG_BUF_LEN];
91         
92         memset(buffer, 0, sizeof(buffer));
93         apr_vsnprintf(buffer, LOG_BUF_LEN-1, fmt, ap);
94         buffer[LOG_BUF_LEN-1] = '\0';
95 
96         if (log_server) {
97             ap_log_error(file, line, APLOG_MODULE_INDEX, (int)level, rv, log_server, "%s",buffer);
98         }
99         else {
100             ap_log_perror(file, line, APLOG_MODULE_INDEX, (int)level, rv, p, "%s", buffer);
101         }
102     }
103 }
104 
105 /**************************************************************************************************/
106 /* mod_ssl interface */
107 
108 static APR_OPTIONAL_FN_TYPE(ssl_is_https) *opt_ssl_is_https;
109 
110 static void init_ssl(void)
111 {
112     opt_ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
113 }
114 
115 /**************************************************************************************************/
116 /* lifecycle */
117 
118 static apr_status_t cleanup_setups(void *dummy)
119 {
120     (void)dummy;
121     log_server = NULL;

Focal lines 175..206
175     return rv;
176 }
177 
178 static apr_status_t setup_store(md_store_t **pstore, md_mod_conf_t *mc, 
179                                 apr_pool_t *p, server_rec *s)
180 {
181     const char *base_dir;
182     apr_status_t rv;
183     
184     base_dir = ap_server_root_relative(p, mc->base_dir);
185     
186     if (APR_SUCCESS != (rv = md_store_fs_init(pstore, p, base_dir))) {
187         ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10046)"setup store for %s", base_dir);
188         goto out;
189     }
190 
191     md_store_fs_set_event_cb(*pstore, store_file_ev, s);
192     if (APR_SUCCESS != (rv = check_group_dir(*pstore, MD_SG_CHALLENGES, p, s))
193         || APR_SUCCESS != (rv = check_group_dir(*pstore, MD_SG_STAGING, p, s))
194         || APR_SUCCESS != (rv = check_group_dir(*pstore, MD_SG_ACCOUNTS, p, s))
195         ) {
196         ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10047) 
197                      "setup challenges directory");
198     }
199     
200 out:
201     return rv;
202 }
203 
204 /**************************************************************************************************/
205 /* post config handling */
206 

Focal lines 194..225
194         || APR_SUCCESS != (rv = check_group_dir(*pstore, MD_SG_ACCOUNTS, p, s))
195         ) {
196         ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10047) 
197                      "setup challenges directory");
198     }
199     
200 out:
201     return rv;
202 }
203 
204 /**************************************************************************************************/
205 /* post config handling */
206 
207 static void merge_srv_config(md_t *md, md_srv_conf_t *base_sc, apr_pool_t *p)
208 {
209     if (!md->sc) {
210         md->sc = base_sc;
211     }
212 
213     if (!md->ca_url) {
214         md->ca_url = md_config_gets(md->sc, MD_CONFIG_CA_URL);
215     }
216     if (!md->ca_proto) {
217         md->ca_proto = md_config_gets(md->sc, MD_CONFIG_CA_PROTO);
218     }
219     if (!md->ca_agreement) {
220         md->ca_agreement = md_config_gets(md->sc, MD_CONFIG_CA_AGREEMENT);
221     }
222     if (md->sc->s->server_admin && strcmp(DEFAULT_ADMIN, md->sc->s->server_admin)) {
223         apr_array_clear(md->contacts);
224         APR_ARRAY_PUSH(md->contacts, const char *) = 
225         md_util_schemify(p, md->sc->s->server_admin, "mailto");
~~~

### modules/md/mod_md.dsp

~~~diff
--- a/modules/md/mod_md.dsp
+++ b/modules/md/mod_md.dsp
@@ -205,6 +205,10 @@ SOURCE=./md_store_fs.c
 # End Source File
 # Begin Source File
 
+SOURCE=./md_tailscale.c
+# End Source File
+# Begin Source File
+
 SOURCE=./md_time.c
 # End Source File
 # Begin Source File

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 197..211
197 # End Source File
198 # Begin Source File
199 
200 SOURCE=./md_time.c
201 # End Source File
202 # Begin Source File
203 
204 SOURCE=./md_util.c
205 # End Source File
206 # Begin Source File
207 
208 SOURCE=..\..\build\win32\httpd.rc
209 # End Source File
210 # End Target
211 # End Project
~~~

### modules/md/mod_md.mak

~~~diff
--- a/modules/md/mod_md.mak
+++ b/modules/md/mod_md.mak
@@ -80,6 +80,7 @@ CLEAN :
 	-@erase "$(INTDIR)\md_status.obj"
 	-@erase "$(INTDIR)\md_store.obj"
 	-@erase "$(INTDIR)\md_store_fs.obj"
+	-@erase "$(INTDIR)\md_tailscale.obj"
 	-@erase "$(INTDIR)\md_time.obj"
 	-@erase "$(INTDIR)\md_util.obj"
 	-@erase "$(INTDIR)\mod_md.obj"
@@ -163,6 +164,7 @@ LINK32_OBJS= \
 	"$(INTDIR)\md_status.obj" \
 	"$(INTDIR)\md_store.obj" \
 	"$(INTDIR)\md_store_fs.obj" \
+	"$(INTDIR)\md_tailscale.obj" \
 	"$(INTDIR)\md_time.obj" \
 	"$(INTDIR)\md_util.obj" \
 	"$(INTDIR)\md_acme.obj" \
@@ -239,6 +241,7 @@ CLEAN :
 	-@erase "$(INTDIR)\md_status.obj"
 	-@erase "$(INTDIR)\md_store.obj"
 	-@erase "$(INTDIR)\md_store_fs.obj"
+	-@erase "$(INTDIR)\md_tailscale.obj"
 	-@erase "$(INTDIR)\md_time.obj"
 	-@erase "$(INTDIR)\md_util.obj"
 	-@erase "$(INTDIR)\mod_md.obj"
@@ -322,6 +325,7 @@ LINK32_OBJS= \
 	"$(INTDIR)\md_status.obj" \
 	"$(INTDIR)\md_store.obj" \
 	"$(INTDIR)\md_store_fs.obj" \
+	"$(INTDIR)\md_tailscale.obj" \
 	"$(INTDIR)\md_time.obj" \
 	"$(INTDIR)\md_util.obj" \
 	"$(INTDIR)\md_acme.obj" \
@@ -565,6 +569,11 @@ SOURCE=./md_store_fs.c
 "$(INTDIR)\md_store_fs.obj" : $(SOURCE) "$(INTDIR)"
 
 
+SOURCE=./md_tailscale.c
+
+"$(INTDIR)\md_tailscale.obj" : $(SOURCE) "$(INTDIR)"
+
+
 SOURCE=./md_time.c
 
 "$(INTDIR)\md_time.obj" : $(SOURCE) "$(INTDIR)"

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 72..103
72 	-@erase "$(INTDIR)\md_curl.obj"
73 	-@erase "$(INTDIR)\md_http.obj"
74 	-@erase "$(INTDIR)\md_json.obj"
75 	-@erase "$(INTDIR)\md_jws.obj"
76 	-@erase "$(INTDIR)\md_log.obj"
77 	-@erase "$(INTDIR)\md_reg.obj"
78 	-@erase "$(INTDIR)\md_result.obj"
79 	-@erase "$(INTDIR)\md_status.obj"
80 	-@erase "$(INTDIR)\md_store.obj"
81 	-@erase "$(INTDIR)\md_store_fs.obj"
82 	-@erase "$(INTDIR)\md_time.obj"
83 	-@erase "$(INTDIR)\md_util.obj"
84 	-@erase "$(INTDIR)\mod_md.obj"
85 	-@erase "$(INTDIR)\mod_md.res"
86 	-@erase "$(INTDIR)\mod_md_config.obj"
87 	-@erase "$(INTDIR)\mod_md_drive.obj"
88 	-@erase "$(INTDIR)\mod_md_status.obj"
89 	-@erase "$(INTDIR)\mod_md_os.obj"
90 	-@erase "$(INTDIR)\mod_md_src.idb"
91 	-@erase "$(INTDIR)\mod_md_src.pdb"
92 	-@erase "$(OUTDIR)\mod_md.exp"
93 	-@erase "$(OUTDIR)\mod_md.lib"
94 	-@erase "$(OUTDIR)\mod_md.pdb"
95 	-@erase "$(OUTDIR)\mod_md.so"
96 
97 "$(OUTDIR)" :
98     if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"
99 
100 CPP=cl.exe
101 CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "../../server/mpm/winnt" /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" $(SSLINC) /I "../../srclib/jansson/include" /I "../../srclib/curl/include" /I "../ssl" /I "../core" /I "../generators" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D ssize_t=long /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_md_src" /FD /I " ../ssl" /c 
102 
103 .c{$(INTDIR)}.obj::

Focal lines 155..186
155 	"$(INTDIR)\md_log.obj" \
156 	"$(INTDIR)\md_reg.obj" \
157 	"$(INTDIR)\md_result.obj" \
158 	"$(INTDIR)\md_status.obj" \
159 	"$(INTDIR)\md_store.obj" \
160 	"$(INTDIR)\md_store_fs.obj" \
161 	"$(INTDIR)\md_time.obj" \
162 	"$(INTDIR)\md_util.obj" \
163 	"$(INTDIR)\md_acme.obj" \
164 	"$(INTDIR)\md_acme_acct.obj" \
165 	"$(INTDIR)\md_acme_authz.obj" \
166 	"$(INTDIR)\md_acme_drive.obj" \
167 	"$(INTDIR)\md_acme_order.obj" \
168 	"$(INTDIR)\md_acmev1_drive.obj" \
169 	"$(INTDIR)\md_acmev2_drive.obj" \
170 	"$(INTDIR)\mod_md.res" \
171 	"..\..\srclib\apr\Release\libapr-1.lib" \
172 	"..\..\srclib\apr-util\Release\libaprutil-1.lib" \
173 	"..\..\Release\libhttpd.lib"
174 
175 "$(OUTDIR)\mod_md.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
176     $(LINK32) @<<
177   $(LINK32_FLAGS) $(LINK32_OBJS)
178 <<
179 
180 TargetPath=.\Release\mod_md.so
181 SOURCE="$(InputPath)"
182 PostBuild_Desc=Embed .manifest
183 DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
184 
185 ALL : $(DS_POSTBUILD_DEP)
186 

Focal lines 231..262
231 	-@erase "$(INTDIR)\md_log.obj"
232 	-@erase "$(INTDIR)\md_reg.obj"
233 	-@erase "$(INTDIR)\md_result.obj"
234 	-@erase "$(INTDIR)\md_status.obj"
235 	-@erase "$(INTDIR)\md_store.obj"
236 	-@erase "$(INTDIR)\md_store_fs.obj"
237 	-@erase "$(INTDIR)\md_time.obj"
238 	-@erase "$(INTDIR)\md_util.obj"
239 	-@erase "$(INTDIR)\mod_md.obj"
240 	-@erase "$(INTDIR)\mod_md.res"
241 	-@erase "$(INTDIR)\mod_md_config.obj"
242 	-@erase "$(INTDIR)\mod_md_drive.obj"
243 	-@erase "$(INTDIR)\mod_md_status.obj"
244 	-@erase "$(INTDIR)\mod_md_os.obj"
245 	-@erase "$(INTDIR)\mod_md_src.idb"
246 	-@erase "$(INTDIR)\mod_md_src.pdb"
247 	-@erase "$(OUTDIR)\mod_md.exp"
248 	-@erase "$(OUTDIR)\mod_md.lib"
249 	-@erase "$(OUTDIR)\mod_md.pdb"
250 	-@erase "$(OUTDIR)\mod_md.so"
251 
252 "$(OUTDIR)" :
253     if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"
254 
255 CPP=cl.exe
256 CPP_PROJ=/nologo /MDd /W3 /Zi /Od /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" $(SSLINC) /I "../../srclib/jansson/include" /I "../../srclib/curl/include" /I "../core" /I "../generators" /I "../ssl" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D ssize_t=long /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_md_src" /FD /EHsc /c 
257 
258 .c{$(INTDIR)}.obj::
259    $(CPP) @<<
260    $(CPP_PROJ) $< 
261 <<
262 
~~~

### modules/md/mod_md_config.c

~~~diff
--- a/modules/md/mod_md_config.c
+++ b/modules/md/mod_md_config.c
@@ -26,6 +26,7 @@
 #include <http_vhost.h>
 
 #include "md.h"
+#include "md_acme.h"
 #include "md_crypt.h"
 #include "md_log.h"
 #include "md_json.h"
@@ -83,6 +84,13 @@ static md_mod_conf_t defmc = {
     "crt.sh",                  /* default cert checker site name */
     "https://crt.sh?q=",       /* default cert checker site url */
     NULL,                      /* CA cert file to use */
+    APR_TIME_C(0),             /* initial cert check delay */
+    apr_time_from_sec(MD_SECS_PER_DAY/2), /* default time between cert checks */
+    apr_time_from_sec(30),     /* minimum delay for retries */
+    13,                        /* retry_failover after 14 errors, with 5s delay ~ half a day */
+    0,                         /* store locks, disabled by default */
+    apr_time_from_sec(5),      /* max time to wait to obaint a store lock */
+    MD_MATCH_ALL,              /* match vhost severname and aliases */
 };
 
 static md_timeslice_t def_renew_window = {
@@ -106,15 +114,19 @@ static md_srv_conf_t defconf = {
     NULL,                      /* pkey spec */
     &def_renew_window,         /* renew window */
     &def_warn_window,          /* warn window */
-    NULL,                      /* ca url */
+    NULL,                      /* ca urls */
     NULL,                      /* ca contact (email) */
-    "ACME",                    /* ca protocol */
+    MD_PROTO_ACME,             /* ca protocol */
     NULL,                      /* ca agreemnent */
     NULL,                      /* ca challenges array */
     NULL,                      /* ca eab kid */
     NULL,                      /* ca eab hmac */
+    NULL,                      /* ACME profile */
+    0,                         /* ACME profile mandatory */
     0,                         /* stapling */
     1,                         /* staple others */
+    1,                         /* ACME ARI renewals */
+    NULL,                      /* dns01_cmd */
     NULL,                      /* currently defined md */
     NULL,                      /* assigned md, post config */
     0,                         /* is_ssl, set during mod_ssl post_config */
@@ -160,15 +172,19 @@ static void srv_conf_props_clear(md_srv_
     sc->pks = NULL;
     sc->renew_window = NULL;
     sc->warn_window = NULL;
-    sc->ca_url = NULL;
+    sc->ca_urls = NULL;
     sc->ca_contact = NULL;
     sc->ca_proto = NULL;
     sc->ca_agreement = NULL;
     sc->ca_challenges = NULL;
     sc->ca_eab_kid = NULL;
     sc->ca_eab_hmac = NULL;
+    sc->profile = NULL;
+    sc->profile_mandatory = DEF_VAL;
     sc->stapling = DEF_VAL;
     sc->staple_others = DEF_VAL;
+    sc->ari_renewals = DEF_VAL;
+    sc->dns01_cmd = NULL;
 }
 
 static void srv_conf_props_copy(md_srv_conf_t *to, const md_srv_conf_t *from)
@@ -180,15 +196,19 @@ static void srv_conf_props_copy(md_srv_c
     to->pks = from->pks;
     to->warn_window = from->warn_window;
     to->renew_window = from->renew_window;
-    to->ca_url = from->ca_url;
+    to->ca_urls = from->ca_urls;
     to->ca_contact = from->ca_contact;
     to->ca_proto = from->ca_proto;
     to->ca_agreement = from->ca_agreement;
     to->ca_challenges = from->ca_challenges;
     to->ca_eab_kid = from->ca_eab_kid;
     to->ca_eab_hmac = from->ca_eab_hmac;
+    to->profile = from->profile;
+    to->profile_mandatory = from->profile_mandatory;
     to->stapling = from->stapling;
     to->staple_others = from->staple_others;
+    to->ari_renewals = from->ari_renewals;
+    to->dns01_cmd = from->dns01_cmd;
 }
 
 static void srv_conf_props_apply(md_t *md, const md_srv_conf_t *from, apr_pool_t *p)
@@ -200,7 +220,7 @@ static void srv_conf_props_apply(md_t *m
     if (from->pks) md->pks = md_pkeys_spec_clone(p, from->pks);
     if (from->renew_window) md->renew_window = from->renew_window;
     if (from->warn_window) md->warn_window = from->warn_window;
-    if (from->ca_url) md->ca_url = from->ca_url;
+    if (from->ca_urls) md->ca_urls = apr_array_copy(p, from->ca_urls);
     if (from->ca_proto) md->ca_proto = from->ca_proto;
     if (from->ca_agreement) md->ca_agreement = from->ca_agreement;
     if (from->ca_contact) {
@@ -211,7 +231,11 @@ static void srv_conf_props_apply(md_t *m
     if (from->ca_challenges) md->ca_challenges = apr_array_copy(p, from->ca_challenges);
     if (from->ca_eab_kid) md->ca_eab_kid = from->ca_eab_kid;
     if (from->ca_eab_hmac) md->ca_eab_hmac = from->ca_eab_hmac;
+    if 
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 18..49
18 
19 #include <apr_lib.h>
20 #include <apr_strings.h>
21 
22 #include <httpd.h>
23 #include <http_core.h>
24 #include <http_config.h>
25 #include <http_log.h>
26 #include <http_vhost.h>
27 
28 #include "md.h"
29 #include "md_crypt.h"
30 #include "md_log.h"
31 #include "md_util.h"
32 #include "mod_md_private.h"
33 #include "mod_md_config.h"
34 
35 #define MD_CMD_MD_SECTION     "<MDomainSet"
36 #define MD_CMD_MD2_SECTION    "<MDomain"
37 
38 #define DEF_VAL     (-1)
39 
40 #ifndef MD_DEFAULT_BASE_DIR
41 #define MD_DEFAULT_BASE_DIR "md"
42 #endif
43 
44 /* Default settings for the global conf */
45 static md_mod_conf_t defmc = {
46     NULL,                      /* list of mds */
47 #if AP_MODULE_MAGIC_AT_LEAST(20180906, 2)
48     NULL,                      /* base dir by default state-dir-relative */
49 #else

Focal lines 75..106
75 };
76 static md_timeslice_t def_warn_window = {
77     MD_TIME_LIFE_NORM,
78     MD_TIME_WARN_WINDOW_DEF,
79 };
80 
81 /* Default server specific setting */
82 static md_srv_conf_t defconf = {
83     "default",                 /* name */
84     NULL,                      /* server_rec */
85     &defmc,                    /* mc */
86     1,                         /* transitive */
87     MD_REQUIRE_OFF,            /* require https */
88     MD_RENEW_AUTO,             /* renew mode */
89     0,                         /* must staple */
90     NULL,                      /* pkey spec */
91     &def_renew_window,         /* renew window */
92     &def_warn_window,          /* warn window */
93     NULL,                      /* ca url */
94     "ACME",                    /* ca protocol */
95     NULL,                      /* ca agreemnent */
96     NULL,                      /* ca challenges array */
97     NULL,                      /* currently defined md */
98     NULL,                      /* assigned md, post config */
99 };
100 
101 static md_mod_conf_t *mod_md_config;
102 
103 static apr_status_t cleanup_mod_config(void *dummy)
104 {
105     (void)dummy;
106     mod_md_config = NULL;

Focal lines 98..129
98     NULL,                      /* assigned md, post config */
99 };
100 
101 static md_mod_conf_t *mod_md_config;
102 
103 static apr_status_t cleanup_mod_config(void *dummy)
104 {
105     (void)dummy;
106     mod_md_config = NULL;
107     return APR_SUCCESS;
108 }
109 
110 static md_mod_conf_t *md_mod_conf_get(apr_pool_t *pool, int create)
111 {
112     if (mod_md_config) {
113         return mod_md_config; /* reused for lifetime of the pool */
114     }
115 
116     if (create) {
117         mod_md_config = apr_pcalloc(pool, sizeof(*mod_md_config));
118         memcpy(mod_md_config, &defmc, sizeof(*mod_md_config));
119         mod_md_config->mds = apr_array_make(pool, 5, sizeof(const md_t *));
120         mod_md_config->unused_names = apr_array_make(pool, 5, sizeof(const md_t *));
121         mod_md_config->watched_names = apr_array_make(pool, 5, sizeof(const md_t *));
122         mod_md_config->env = apr_table_make(pool, 10);
123         mod_md_config->init_errors = apr_hash_make(pool);
124          
125         apr_pool_cleanup_register(pool, NULL, cleanup_mod_config, apr_pool_cleanup_null);
126     }
127     
128     return mod_md_config;
129 }
~~~

### modules/md/mod_md_config.h

~~~diff
--- a/modules/md/mod_md_config.h
+++ b/modules/md/mod_md_config.h
@@ -24,7 +24,6 @@ struct md_ocsp_reg_t;
 struct md_pkeys_spec_t;
 
 typedef enum {
-    MD_CONFIG_CA_URL,
     MD_CONFIG_CA_CONTACT,
     MD_CONFIG_CA_PROTO,
     MD_CONFIG_BASE_DIR,
@@ -40,8 +39,16 @@ typedef enum {
     MD_CONFIG_MESSGE_CMD,
     MD_CONFIG_STAPLING,
     MD_CONFIG_STAPLE_OTHERS,
+    MD_CONFIG_CA_PROFILE,
+    MD_CONFIG_CA_PROFILE_MANDATORY,
+    MD_CONFIG_ARI_RENEWALS,
 } md_config_var_t;
 
+typedef enum {
+    MD_MATCH_ALL,
+    MD_MATCH_SERVERNAMES,
+} md_match_mode_t;
+
 typedef struct md_mod_conf_t md_mod_conf_t;
 struct md_mod_conf_t {
     apr_array_header_t *mds;           /* all md_t* defined in the config, shared */
@@ -71,6 +78,13 @@ struct md_mod_conf_t {
     const char *cert_check_name;       /* name of the linked certificate check site */
     const char *cert_check_url;        /* url "template for" checking a certificate */
     const char *ca_certs;              /* root certificates to use for connections */
+    apr_time_t initial_delay;          /* how long to delay the first cert renewal check */
+    apr_time_t check_interval;         /* duration between cert renewal checks */
+    apr_time_t min_delay;              /* minimum delay for retries */
+    int retry_failover;                /* number of errors to trigger CA failover */
+    int use_store_locks;               /* use locks when updating store */
+    apr_time_t lock_wait_timeout;      /* fail after this time when unable to obtain lock */
+    md_match_mode_t match_mode;        /* how dns names are match to vhosts */
 };
 
 typedef struct md_srv_conf_t {
@@ -86,16 +100,21 @@ typedef struct md_srv_conf_t {
     md_timeslice_t *renew_window;      /* time before expiration that starts renewal */
     md_timeslice_t *warn_window;       /* time before expiration that warning are sent out */
     
-    const char *ca_url;                /* url of CA certificate service */
+    struct apr_array_header_t *ca_urls; /* urls of CAs */
     const char *ca_contact;            /* contact email registered to account */
     const char *ca_proto;              /* protocol used vs CA (e.g. ACME) */
     const char *ca_agreement;          /* accepted agreement uri between CA and user */ 
     struct apr_array_header_t *ca_challenges; /* challenge types configured */
     const char *ca_eab_kid;            /* != NULL, external account binding keyid */
     const char *ca_eab_hmac;           /* != NULL, external account binding hmac */
+    const char *profile;               /* != NULL, ACME order profile */
+    int profile_mandatory;             /* if ACME profile, when set, is mandatory */
 
     int stapling;                      /* OCSP stapling enabled */
     int staple_others;                 /* Provide OCSP stapling for non-MD certificates */
+    int ari_renewals;                  /* ACME ARI extension enabled */
+
+    const char *dns01_cmd;             /* DNS challenge command, override global command */
 
     md_t *current;                     /* md currently defined in <MDomainSet xxx> section */
     struct apr_array_header_t *assigned; /* post_config: MDs that apply to this server */

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 16..47
16 
17 #ifndef mod_md_md_config_h
18 #define mod_md_md_config_h
19 
20 struct apr_hash_t;
21 struct md_store_t;
22 struct md_reg_t;
23 struct md_pkey_spec_t;
24 
25 typedef enum {
26     MD_CONFIG_CA_URL,
27     MD_CONFIG_CA_PROTO,
28     MD_CONFIG_BASE_DIR,
29     MD_CONFIG_CA_AGREEMENT,
30     MD_CONFIG_DRIVE_MODE,
31     MD_CONFIG_LOCAL_80,
32     MD_CONFIG_LOCAL_443,
33     MD_CONFIG_RENEW_WINDOW,
34     MD_CONFIG_WARN_WINDOW,
35     MD_CONFIG_TRANSITIVE,
36     MD_CONFIG_PROXY,
37     MD_CONFIG_REQUIRE_HTTPS,
38     MD_CONFIG_MUST_STAPLE,
39     MD_CONFIG_NOTIFY_CMD,
40     MD_CONFIG_MESSGE_CMD,
41 } md_config_var_t;
42 
43 typedef struct md_mod_conf_t md_mod_conf_t;
44 struct md_mod_conf_t {
45     apr_array_header_t *mds;           /* all md_t* defined in the config, shared */
46     const char *base_dir;              /* base dir for store */
47     const char *proxy_url;             /* proxy url to use (or NULL) */

Focal lines 32..63
32     MD_CONFIG_LOCAL_443,
33     MD_CONFIG_RENEW_WINDOW,
34     MD_CONFIG_WARN_WINDOW,
35     MD_CONFIG_TRANSITIVE,
36     MD_CONFIG_PROXY,
37     MD_CONFIG_REQUIRE_HTTPS,
38     MD_CONFIG_MUST_STAPLE,
39     MD_CONFIG_NOTIFY_CMD,
40     MD_CONFIG_MESSGE_CMD,
41 } md_config_var_t;
42 
43 typedef struct md_mod_conf_t md_mod_conf_t;
44 struct md_mod_conf_t {
45     apr_array_header_t *mds;           /* all md_t* defined in the config, shared */
46     const char *base_dir;              /* base dir for store */
47     const char *proxy_url;             /* proxy url to use (or NULL) */
48     struct md_reg_t *reg;              /* md registry instance, singleton, shared */
49 
50     int local_80;                      /* On which port http:80 arrives */
51     int local_443;                     /* On which port https:443 arrives */
52     int can_http;                      /* Does someone listen to the local port 80 equivalent? */
53     int can_https;                     /* Does someone listen to the local port 443 equivalent? */
54     int manage_base_server;            /* If base server outside vhost may be managed */
55     int hsts_max_age;                  /* max-age of HSTS (rfc6797) header */
56     const char *hsts_header;           /* computed HTST header to use or NULL */
57     apr_array_header_t *unused_names;  /* post config, names of all MDs not assigned to a vhost */
58     apr_array_header_t *watched_names; /* post config, names of all MDs that we need to watch */
59     struct apr_hash_t *init_errors;    /* init errors reported with MD name as key */
60 
61     const char *notify_cmd;            /* notification command to execute on signup/renew */
62     const char *message_cmd;           /* message command to execute on signup/renew/warnings */
63     struct apr_table_t *env;           /* environment for operation */

Focal lines 63..94
63     struct apr_table_t *env;           /* environment for operation */
64     int dry_run;                       /* != 0 iff config dry run */
65     int server_status_enabled;         /* if module should add to server-status handler */
66     int certificate_status_enabled;    /* if module should expose /.httpd/certificate-status */
67 };
68 
69 typedef struct md_srv_conf_t {
70     const char *name;
71     const server_rec *s;               /* server this config belongs to */
72     md_mod_conf_t *mc;                 /* global config settings */
73     
74     int transitive;                    /* != 0 iff VirtualHost names/aliases are auto-added */
75     md_require_t require_https;        /* If MDs require https: access */
76     int renew_mode;                    /* mode of obtaining credentials */
77     int must_staple;                   /* certificates should set the OCSP Must Staple extension */
78     struct md_pkey_spec_t *pkey_spec;  /* specification for generating private keys */
79     const md_timeslice_t *renew_window; /* time before expiration that starts renewal */
80     const md_timeslice_t *warn_window;  /* time before expiration that warning are sent out */
81     
82     const char *ca_url;                /* url of CA certificate service */
83     const char *ca_proto;              /* protocol used vs CA (e.g. ACME) */
84     const char *ca_agreement;          /* accepted agreement uri between CA and user */ 
85     struct apr_array_header_t *ca_challenges; /* challenge types configured */
86 
87     md_t *current;                     /* md currently defined in <MDomainSet xxx> section */
88     md_t *assigned;                    /* post_config: MD that applies to this server or NULL */
89 } md_srv_conf_t;
90 
91 void *md_config_create_svr(apr_pool_t *pool, server_rec *s);
92 void *md_config_merge_svr(apr_pool_t *pool, void *basev, void *addv);
93 
94 extern const command_rec md_cmds[];
~~~

### modules/md/mod_md_drive.c

~~~diff
--- a/modules/md/mod_md_drive.c
+++ b/modules/md/mod_md_drive.c
@@ -100,22 +100,80 @@ static void process_drive_job(md_renew_c
     }
     
     if (md_will_renew_cert(md)) {
-        /* Renew the MDs credentials in a STAGING area. Might be invoked repeatedly 
+        /* Renew the MDs credentials in a STAGING area. Might be invoked repeatedly
          * without discarding previous/intermediate results.
          * Only returns SUCCESS when the renewal is complete, e.g. STAGING has a
          * complete set of new credentials.
          */
-        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10052) 
+        apr_time_t renew_at, now;
+        const char *ari_explain_url = NULL;
+
+        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10052)
                      "md(%s): state=%d, driving", job->mdomain, md->state);
 
-        if (!md_reg_should_renew(dctx->mc->reg, md, dctx->p)) {
-            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10053) 
-                         "md(%s): no need to renew", job->mdomain);
-            goto expiry;
+        renew_at = md_reg_renew_at(dctx->mc->reg, md, ptemp);
+        now = apr_time_now();
+
+        if (md->stapling && dctx->mc->ocsp &&
+            md_reg_has_revoked_certs(dctx->mc->reg, dctx->mc->ocsp, md, ptemp)) {
+            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10500)
+                         "md(%s): need to renew, OCSP reports revoked "
+                         "certificate(s)", job->mdomain);
+        }
+        else if (!renew_at || renew_at <= now) {
+            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10512)
+                         "md(%s): need to renew now", job->mdomain);
+        }
+        else {
+            apr_time_t ari_renew_at = 0;
+            char ts[APR_RFC822_DATE_LEN];
+
+            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10513)
+                         "md(%s): ARI is %senabled", job->mdomain,
+                         md->ari_renewals? "" : "not ");
+            if (md->ari_renewals)
+                ari_renew_at = md_reg_ari_renew_at(&ari_explain_url, dctx->mc->reg, md,
+                                                   dctx->mc->env, result, ptemp);
+            if (!ari_renew_at || (ari_renew_at > renew_at)) {
+                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10514)
+                             "md(%s): %sup for configured renewal in %s",
+                             job->mdomain,
+                             (ari_renew_at || !md->ari_renewals) ? "" : "no ARI available, ",
+                             md_duration_print(ptemp, renew_at - now));
+                goto expiry;
+            }
+            else if (ari_renew_at > now) {
+                long secs = (long)apr_time_sec(ari_renew_at - now);
+                apr_rfc822_date(ts, ari_renew_at);
+                if (ari_explain_url) {
+                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, dctx->s, APLOGNO(10515)
+                                 "md(%s): CA advises renew via ARI at %s"
+                                 ", for explanation see %s",
+                                 job->mdomain, ts, ari_explain_url);
+                }
+                else
+                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10516)
+                                 "md(%s): CA advises renew via ARI at %s",
+                                 job->mdomain, ts);
+                if (secs < MD_SECS_PER_DAY) { /* earlier than regular run */
+                  job->next_run = ari_renew_at;
+                }
+                goto expiry;
+            }
+            /* ARI says we should renew *now* */
+            if (ari_explain_url) {
+                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, dctx->s, APLOGNO(10517)
+                             "md(%s): CA advises renew via ARI now"
+                             ", for explanation see %s",
+                             job->mdomain, ari_explain_url);
+            }
+            else
+                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10518)
+                             "md(%s): CA advises renew via ARI now", job->mdomain);
         }
     
         /* The (possibly configured) event handler may veto renewals. This
-         * is used in cluster installtations, see #233. */
+         * is used in cluster installations, see #233. */
         rv = md_event_raise("renewing
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 92..123
92                 sep = ": ";
93             }
94             if (result->detail) {
95                 msg = apr_psprintf(result->p, "%s%s%s", msg, sep, result->detail);
96                 sep = ", ";
97             }
98             if (result->problem) {
99                 msg = apr_psprintf(result->p, "%s%sproblem: %s", msg, sep, result->problem);
100                 sep = " ";
101             }
102             md_job_log_append(ctx->job, "progress", NULL, msg);
103 
104             if (apr_time_msec(now - ctx->last_save) > 500) {
105                 md_job_save(ctx->job, ctx->reg, MD_SG_STAGING, result, ctx->p);
106                 ctx->last_save = now;
107             }
108         }
109     }
110 }
111 
112 static void job_result_observation_start(md_job_t *job, md_result_t *result, 
113                                          md_reg_t *reg, apr_pool_t *p)
114 {
115     md_job_result_ctx *ctx;
116 
117     ctx = apr_pcalloc(p, sizeof(*ctx));
118     ctx->p = p;
119     ctx->job = job;
120     ctx->reg = reg;
121     ctx->last = md_result_md_make(p, APR_SUCCESS);
122     md_result_assign(ctx->last, result);
123     md_result_on_change(result, job_result_update, ctx);

Focal lines 117..148
117     ctx = apr_pcalloc(p, sizeof(*ctx));
118     ctx->p = p;
119     ctx->job = job;
120     ctx->reg = reg;
121     ctx->last = md_result_md_make(p, APR_SUCCESS);
122     md_result_assign(ctx->last, result);
123     md_result_on_change(result, job_result_update, ctx);
124 }
125 
126 static void job_result_observation_end(md_job_t *job, md_result_t *result)
127 {
128     (void)job;
129     md_result_on_change(result, NULL, NULL);
130 } 
131 
132 static apr_time_t calc_err_delay(int err_count)
133 {
134     apr_time_t delay = 0;
135     
136     if (err_count > 0) {
137         /* back off duration, depending on the errors we encounter in a row */
138         delay = apr_time_from_sec(5 << (err_count - 1));
139         if (delay > apr_time_from_sec(60*60)) {
140             delay = apr_time_from_sec(60*60);
141         }
142     }
143     return delay;
144 }
145 
146 static apr_status_t send_notification(md_drive_ctx *dctx, md_job_t *job, const md_t *md, 
147                                       const char *reason, md_result_t *result, apr_pool_t *ptemp)
148 {

Focal lines 146..177
146 static apr_status_t send_notification(md_drive_ctx *dctx, md_job_t *job, const md_t *md, 
147                                       const char *reason, md_result_t *result, apr_pool_t *ptemp)
148 {
149     const char * const *argv;
150     const char *cmdline;
151     int exit_code;
152     apr_status_t rv = APR_SUCCESS;            
153     
154     if (!strcmp("renewed", reason)) {
155         if (dctx->mc->notify_cmd) {
156             cmdline = apr_psprintf(ptemp, "%s %s", dctx->mc->notify_cmd, md->name); 
157             apr_tokenize_to_argv(cmdline, (char***)&argv, ptemp);
158             rv = md_util_exec(ptemp, argv[0], argv, &exit_code);
159             
160             if (APR_SUCCESS == rv && exit_code) rv = APR_EGENERAL;
161             if (APR_SUCCESS != rv) {
162                 if (!result) result = md_result_make(ptemp, rv);
163                 md_result_problem_printf(result, rv, MD_RESULT_LOG_ID(APLOGNO(10108)), 
164                                          "MDNotifyCmd %s failed with exit code %d.", 
165                                          dctx->mc->notify_cmd, exit_code);
166                 md_result_log(result, MD_LOG_ERR);
167                 md_job_log_append(job, "notify-error", result->problem, result->detail);
168                 goto leave;
169             }
170         }
171         ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, dctx->s, APLOGNO(10059) 
172                      "The Managed Domain %s has been setup and changes "
173                      "will be activated on next (graceful) server restart.", md->name);
174     }
175     if (dctx->mc->message_cmd) {
176         cmdline = apr_psprintf(ptemp, "%s %s %s", dctx->mc->message_cmd, reason, md->name); 
177         ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, dctx->s, "Message command: %s", cmdline);
~~~

### modules/md/mod_md_status.c

~~~diff
--- a/modules/md/mod_md_status.c
+++ b/modules/md/mod_md_status.c
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
- 
+
 #include <assert.h>
 #include <apr_optional.h>
 #include <apr_time.h>
@@ -55,6 +55,7 @@
 
 #define APACHE_PREFIX               "/.httpd/"
 #define MD_STATUS_RESOURCE          APACHE_PREFIX"certificate-status"
+#define HTML_STATUS(X)              (!((X)->flags & AP_STATUS_SHORT))
 
 int md_http_cert_status(request_rec *r)
 {
@@ -66,13 +67,13 @@ int md_http_cert_status(request_rec *r)
     const char *keyname;
     apr_bucket_brigade *bb;
     apr_status_t rv;
-    
+
     if (!r->parsed_uri.path || strcmp(MD_STATUS_RESOURCE, r->parsed_uri.path))
         return DECLINED;
-        
+
     ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                   "requesting status for: %s", r->hostname);
-    
+
     /* We are looking for information about a staged certificate */
     sc = ap_get_module_config(r->server->module_config, &md_module);
     if (!sc || !sc->mc || !sc->mc->reg || !sc->mc->certificate_status_enabled) return DECLINED;
@@ -84,7 +85,7 @@ int md_http_cert_status(request_rec *r)
                       "md(%s): status supports only GET", md->name);
         return HTTP_NOT_IMPLEMENTED;
     }
-    
+
     ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                   "requesting status for MD: %s", md->name);
 
@@ -94,7 +95,7 @@ int md_http_cert_status(request_rec *r)
                       "loading md status for %s", md->name);
         return HTTP_INTERNAL_SERVER_ERROR;
     }
-    
+
     ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                   "status for MD: %s is %s", md->name, md_json_writep(mdj, r->pool, MD_JSON_FMT_INDENT));
 
@@ -124,23 +125,23 @@ int md_http_cert_status(request_rec *r)
         }
         md_json_setj(cj, resp, keyname, NULL );
     }
-    
+
     if (md_json_has_key(mdj, MD_KEY_RENEWAL, NULL)) {
            /* copy over the information we want to make public about this:
             *  - when not finished, add an empty object to indicate something is going on
             *  - when a certificate is staged, add the information from that */
            cj = md_json_getj(mdj, MD_KEY_RENEWAL, MD_KEY_CERT, NULL);
-           cj = cj? cj : md_json_create(r->pool);; 
+           cj = cj? cj : md_json_create(r->pool);
            md_json_setj(cj, resp, MD_KEY_RENEWAL, MD_KEY_CERT, NULL);
      }
-    
+
     ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "md[%s]: sending status", md->name);
-    apr_table_set(r->headers_out, "Content-Type", "application/json"); 
+    apr_table_set(r->headers_out, "Content-Type", "application/json");
     bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
     md_json_writeb(resp, MD_JSON_FMT_INDENT, bb);
     ap_pass_brigade(r->output_filters, bb);
     apr_brigade_cleanup(bb);
-    
+
     return DONE;
 }
 
@@ -151,10 +152,12 @@ typedef struct {
     apr_pool_t *p;
     const md_mod_conf_t *mc;
     apr_bucket_brigade *bb;
+    int flags;
+    const char *prefix;
     const char *separator;
 } status_ctx;
 
-typedef struct status_info status_info; 
+typedef struct status_info status_info;
 
 static void add_json_val(status_ctx *ctx, md_json_t *j);
 
@@ -179,13 +182,19 @@ static void si_val_status(status_ctx *ct
         case MD_S_EXPIRED_DEPRECATED:
         case MD_S_COMPLETE:
             until = md_json_get_time(mdj, MD_KEY_CERT, MD_KEY_VALID, MD_KEY_UNTIL, NULL);
-            s = (!until || until > apr_time_now())? "good" : "expired"; 
+            s = (!until || until > apr_time_now())? "good" : "expired";
             break;
         case MD_S_ERROR: s = "error"; break;
         case MD_S_MISSING_INFORMATION: s = "missing information"; break;
         default: break;
     }
-    apr_brigade_puts(ctx->bb, NULL, NULL, s);
+    if (HTML_STATUS(ctx)) {
+        apr_brigade_puts(ctx->bb, NULL, NULL, s);
+    }
+    else {
+        apr_brigade_printf(ctx->bb, NULL, NULL, "%s%s: %s\n",
+                           ctx->prefix, info->label, s);
+    }
 }
 
 static void si_val_url(status_ctx *ctx, md_json_t *mdj, const status_info *info)
@@ -195,19 +204,28 @@ static void si_val_url(status_ctx *ctx,
     s = url = md_json_gets(mdj, info->key, NULL);
     if (!url) return;
     s = md_get_ca_name_from_url(ctx->p, url);
-    apr_brigade_printf(ctx->bb, NULL, NULL, "<a href='%s'>%s</a>",
-                       ap_escape_html2(ctx->p, url, 1)
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 5..36
5  * (the "License"); you may not use this file except in compliance with
6  * the License.  You may obtain a copy of the License at
7  *
8  *     http://www.apache.org/licenses/LICENSE-2.0
9  *
10  * Unless required by applicable law or agreed to in writing, software
11  * distributed under the License is distributed on an "AS IS" BASIS,
12  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
13  * See the License for the specific language governing permissions and
14  * limitations under the License.
15  */
16  
17 #include <assert.h>
18 #include <apr_optional.h>
19 #include <apr_time.h>
20 #include <apr_date.h>
21 #include <apr_strings.h>
22 
23 #include <httpd.h>
24 #include <http_core.h>
25 #include <http_protocol.h>
26 #include <http_request.h>
27 #include <http_log.h>
28 
29 #include "mod_status.h"
30 
31 #include "md.h"
32 #include "md_curl.h"
33 #include "md_crypt.h"
34 #include "md_http.h"
35 #include "md_json.h"
36 #include "md_status.h"

Focal lines 47..78
47 #include "mod_md_private.h"
48 #include "mod_md_config.h"
49 #include "mod_md_drive.h"
50 #include "mod_md_status.h"
51 
52 /**************************************************************************************************/
53 /* Certificate status */
54 
55 #define APACHE_PREFIX               "/.httpd/"
56 #define MD_STATUS_RESOURCE          APACHE_PREFIX"certificate-status"
57 
58 int md_http_cert_status(request_rec *r)
59 {
60     md_json_t *resp, *j, *mdj, *certj;
61     const md_srv_conf_t *sc;
62     const md_t *md;
63     apr_bucket_brigade *bb;
64     apr_status_t rv;
65     
66     if (!r->parsed_uri.path || strcmp(MD_STATUS_RESOURCE, r->parsed_uri.path))
67         return DECLINED;
68         
69     ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
70                   "requesting status for: %s", r->hostname);
71     
72     /* We are looking for information about a staged certificate */
73     sc = ap_get_module_config(r->server->module_config, &md_module);
74     if (!sc || !sc->mc || !sc->mc->reg || !sc->mc->certificate_status_enabled) return DECLINED;
75     md = md_get_by_domain(sc->mc->mds, r->hostname);
76     if (!md) return DECLINED;
77 
78     if (r->method_number != M_GET) {

Focal lines 58..89
58 int md_http_cert_status(request_rec *r)
59 {
60     md_json_t *resp, *j, *mdj, *certj;
61     const md_srv_conf_t *sc;
62     const md_t *md;
63     apr_bucket_brigade *bb;
64     apr_status_t rv;
65     
66     if (!r->parsed_uri.path || strcmp(MD_STATUS_RESOURCE, r->parsed_uri.path))
67         return DECLINED;
68         
69     ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
70                   "requesting status for: %s", r->hostname);
71     
72     /* We are looking for information about a staged certificate */
73     sc = ap_get_module_config(r->server->module_config, &md_module);
74     if (!sc || !sc->mc || !sc->mc->reg || !sc->mc->certificate_status_enabled) return DECLINED;
75     md = md_get_by_domain(sc->mc->mds, r->hostname);
76     if (!md) return DECLINED;
77 
78     if (r->method_number != M_GET) {
79         ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
80                       "md(%s): status supports only GET", md->name);
81         return HTTP_NOT_IMPLEMENTED;
82     }
83     
84     ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
85                   "requesting status for MD: %s", md->name);
86 
87     if (APR_SUCCESS != (rv = md_status_get_md_json(&mdj, md, sc->mc->reg, r->pool))) {
88         ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10175)
89                       "loading md status for %s", md->name);
~~~

## CVE-2025-55753-3.patch

Previous result: skipped

Touched paths: modules/md/md_version.h, modules/md/mod_md_config.c, modules/md/mod_md_ocsp.c

### Dry run fuzz=0 exit=1

~~~text
checking file modules/md/md_version.h
Hunk #1 FAILED at 27.
Hunk #2 FAILED at 35.
2 out of 2 hunks FAILED
checking file modules/md/mod_md_config.c
Hunk #1 FAILED at 282.
1 out of 1 hunk FAILED
can't find file to patch at input line 66
Perhaps you used the wrong -p or --strip option?
The text leading up to this was:
--------------------------
|diff --git a/modules/md/mod_md_ocsp.c b/modules/md/mod_md_ocsp.c
|index 1d1e2827de0..78d0ace5e17 100644
|--- a/modules/md/mod_md_ocsp.c
|+++ b/modules/md/mod_md_ocsp.c
--------------------------
No file to patch.  Skipping patch.
1 out of 1 hunk ignored

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file modules/md/md_version.h
Hunk #1 FAILED at 27.
Hunk #2 FAILED at 35.
2 out of 2 hunks FAILED
checking file modules/md/mod_md_config.c
Hunk #1 FAILED at 282.
1 out of 1 hunk FAILED
can't find file to patch at input line 66
Perhaps you used the wrong -p or --strip option?
The text leading up to this was:
--------------------------
|diff --git a/modules/md/mod_md_ocsp.c b/modules/md/mod_md_ocsp.c
|index 1d1e2827de0..78d0ace5e17 100644
|--- a/modules/md/mod_md_ocsp.c
|+++ b/modules/md/mod_md_ocsp.c
--------------------------
No file to patch.  Skipping patch.
1 out of 1 hunk ignored

~~~

### Dry run fuzz=2 exit=1

~~~text
checking file modules/md/md_version.h
Hunk #1 FAILED at 27.
Hunk #2 FAILED at 35.
2 out of 2 hunks FAILED
checking file modules/md/mod_md_config.c
Hunk #1 FAILED at 282.
1 out of 1 hunk FAILED
can't find file to patch at input line 66
Perhaps you used the wrong -p or --strip option?
The text leading up to this was:
--------------------------
|diff --git a/modules/md/mod_md_ocsp.c b/modules/md/mod_md_ocsp.c
|index 1d1e2827de0..78d0ace5e17 100644
|--- a/modules/md/mod_md_ocsp.c
|+++ b/modules/md/mod_md_ocsp.c
--------------------------
No file to patch.  Skipping patch.
1 out of 1 hunk ignored

~~~

### modules/md/md_version.h

~~~diff
--- a/modules/md/md_version.h
+++ b/modules/md/md_version.h
@@ -27,7 +27,7 @@
  * @macro
  * Version number of the md module as c string
  */
-#define MOD_MD_VERSION "2.6.6"
+#define MOD_MD_VERSION "2.6.7-git"
 
 /**
  * @macro
@@ -35,7 +35,7 @@
  * release. This is a 24 bit number with 8 bits for major number, 8 bits
  * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
  */
-#define MOD_MD_VERSION_NUM 0x020606
+#define MOD_MD_VERSION_NUM 0x020607
 
 #define MD_ACME_DEF_URL         "https://acme-v02.api.letsencrypt.org/directory"
 
diff --git a/modules/md/mod_md_config.c b/modules/md/mod_md_config.c
index d6807c9caf6..96887145376 100644

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 19..42
19 
20 #undef PACKAGE_VERSION
21 #undef PACKAGE_TARNAME
22 #undef PACKAGE_STRING
23 #undef PACKAGE_NAME
24 #undef PACKAGE_BUGREPORT
25 
26 /**
27  * @macro
28  * Version number of the md module as c string
29  */
30 #define MOD_MD_VERSION "2.0.10"
31 
32 /**
33  * @macro
34  * Numerical representation of the version number of the md module
35  * release. This is a 24 bit number with 8 bits for major number, 8 bits
36  * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
37  */
38 #define MOD_MD_VERSION_NUM 0x02000a
39 
40 #define MD_ACME_DEF_URL    "https://acme-v02.api.letsencrypt.org/directory"
41 
42 #endif /* mod_md_md_version_h */

Focal lines 27..42
27  * @macro
28  * Version number of the md module as c string
29  */
30 #define MOD_MD_VERSION "2.0.10"
31 
32 /**
33  * @macro
34  * Numerical representation of the version number of the md module
35  * release. This is a 24 bit number with 8 bits for major number, 8 bits
36  * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
37  */
38 #define MOD_MD_VERSION_NUM 0x02000a
39 
40 #define MD_ACME_DEF_URL    "https://acme-v02.api.letsencrypt.org/directory"
41 
42 #endif /* mod_md_md_version_h */
~~~

### modules/md/mod_md_config.c

~~~diff
--- a/modules/md/mod_md_config.c
+++ b/modules/md/mod_md_config.c
@@ -282,6 +282,7 @@ static void *md_config_merge(apr_pool_t *pool, void *basev, void *addv)
     nsc->profile = add->profile? add->profile : base->profile;
     nsc->profile_mandatory = (add->profile_mandatory != DEF_VAL)? add->profile_mandatory : base->profile_mandatory;
     nsc->stapling = (add->stapling != DEF_VAL)? add->stapling : base->stapling;
+    nsc->staple_others = (add->staple_others != DEF_VAL)? add->staple_others : base->staple_others;
     nsc->ari_renewals = (add->ari_renewals != DEF_VAL)? add->ari_renewals : base->ari_renewals;
     nsc->dns01_cmd = (add->dns01_cmd)? add->dns01_cmd : base->dns01_cmd;
     nsc->current = NULL;
diff --git a/modules/md/mod_md_ocsp.c b/modules/md/mod_md_ocsp.c
index 1d1e2827de0..78d0ace5e17 100644

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 274..305
274     if (!apr_strnatcasecmp("auto", value)) {
275         *ptransitive = 1;
276         return NULL;
277     }
278     else if (!apr_strnatcasecmp("manual", value)) {
279         *ptransitive = 0;
280         return NULL;
281     }
282     return "unknown value, use \"auto|manual\"";
283 }
284 
285 static const char *md_config_sec_start(cmd_parms *cmd, void *mconfig, const char *arg)
286 {
287     md_srv_conf_t *sc;
288     md_srv_conf_t save;
289     const char *endp;
290     const char *err, *name;
291     apr_array_header_t *domains;
292     md_t *md;
293     int transitive = -1;
294     
295     (void)mconfig;
296     if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
297         return err;
298     }
299         
300     sc = md_config_get(cmd->server);
301     endp = ap_strrchr_c(arg, '>');
302     if (endp == NULL) {
303         return  MD_CMD_MD_SECTION "> directive missing closing '>'";
304     }
305 
~~~

### modules/md/mod_md_ocsp.c

~~~diff
--- a/modules/md/mod_md_ocsp.c
+++ b/modules/md/mod_md_ocsp.c
@@ -61,8 +61,18 @@ int md_ocsp_prime_status(server_rec *s, apr_pool_t *p,
     apr_array_header_t *chain;
     apr_status_t rv = APR_ENOENT;
 
+    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s, "ocsp prime status call for: %s",
+                 s->server_hostname);
     sc = md_config_get(s);
-    if (!staple_here(sc)) goto cleanup;
+    if (!staple_here(sc)) {
+        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,
+                     "ocsp prime does not apply here: server=%s, sc=%d"
+                     "ocsp=%d, conf-ocsp=%d conf-others=%d",
+                     s->server_hostname, !!sc, sc? !!sc->mc->ocsp : 0,
+                     md_config_geti(sc, MD_CONFIG_STAPLING),
+                     md_config_geti(sc, MD_CONFIG_STAPLE_OTHERS));
+        goto cleanup;
+    }
 
     md = ((sc->assigned && sc->assigned->nelts == 1)?
           APR_ARRAY_IDX(sc->assigned, 0, const md_t*) : NULL);

~~~

Source file missing in Focal.

## CVE-2026-29168.patch

Previous result: skipped

Touched paths: modules/md/md_ocsp.c

### Dry run fuzz=0 exit=1

~~~text
can't find file to patch at input line 20
Perhaps you used the wrong -p or --strip option?
The text leading up to this was:
--------------------------
|From 5b1edb79aa2d0f8e4424de64879c46c1942e460a Mon Sep 17 00:00:00 2001
|From: Eric Covener <covener@apache.org>
|Date: Sun, 26 Apr 2026 16:02:37 +0000
|Subject: [PATCH] Merge r1933351 from trunk:
|
|ocsp limits
|
|
|
|
|git-svn-id: https://svn.apache.org/repos/asf/httpd/httpd/branches/2.4.x@1933352 13f79535-47bb-0310-9956-ffa450edef68
|---
| modules/md/md_ocsp.c | 22 +++++++++++++++++++++-
| 1 file changed, 21 insertions(+), 1 deletion(-)
|
|diff --git a/modules/md/md_ocsp.c b/modules/md/md_ocsp.c
|index d2dfd73b68b..b44458676f7 100644
|--- a/modules/md/md_ocsp.c
|+++ b/modules/md/md_ocsp.c
--------------------------
No file to patch.  Skipping patch.
2 out of 2 hunks ignored

~~~

### Dry run fuzz=1 exit=1

~~~text
can't find file to patch at input line 20
Perhaps you used the wrong -p or --strip option?
The text leading up to this was:
--------------------------
|From 5b1edb79aa2d0f8e4424de64879c46c1942e460a Mon Sep 17 00:00:00 2001
|From: Eric Covener <covener@apache.org>
|Date: Sun, 26 Apr 2026 16:02:37 +0000
|Subject: [PATCH] Merge r1933351 from trunk:
|
|ocsp limits
|
|
|
|
|git-svn-id: https://svn.apache.org/repos/asf/httpd/httpd/branches/2.4.x@1933352 13f79535-47bb-0310-9956-ffa450edef68
|---
| modules/md/md_ocsp.c | 22 +++++++++++++++++++++-
| 1 file changed, 21 insertions(+), 1 deletion(-)
|
|diff --git a/modules/md/md_ocsp.c b/modules/md/md_ocsp.c
|index d2dfd73b68b..b44458676f7 100644
|--- a/modules/md/md_ocsp.c
|+++ b/modules/md/md_ocsp.c
--------------------------
No file to patch.  Skipping patch.
2 out of 2 hunks ignored

~~~

### Dry run fuzz=2 exit=1

~~~text
can't find file to patch at input line 20
Perhaps you used the wrong -p or --strip option?
The text leading up to this was:
--------------------------
|From 5b1edb79aa2d0f8e4424de64879c46c1942e460a Mon Sep 17 00:00:00 2001
|From: Eric Covener <covener@apache.org>
|Date: Sun, 26 Apr 2026 16:02:37 +0000
|Subject: [PATCH] Merge r1933351 from trunk:
|
|ocsp limits
|
|
|
|
|git-svn-id: https://svn.apache.org/repos/asf/httpd/httpd/branches/2.4.x@1933352 13f79535-47bb-0310-9956-ffa450edef68
|---
| modules/md/md_ocsp.c | 22 +++++++++++++++++++++-
| 1 file changed, 21 insertions(+), 1 deletion(-)
|
|diff --git a/modules/md/md_ocsp.c b/modules/md/md_ocsp.c
|index d2dfd73b68b..b44458676f7 100644
|--- a/modules/md/md_ocsp.c
|+++ b/modules/md/md_ocsp.c
--------------------------
No file to patch.  Skipping patch.
2 out of 2 hunks ignored

~~~

### modules/md/md_ocsp.c

~~~diff
--- a/modules/md/md_ocsp.c
+++ b/modules/md/md_ocsp.c
@@ -46,7 +46,21 @@
 #include "md_ocsp.h"
 
 #define MD_OCSP_ID_LENGTH   SHA_DIGEST_LENGTH
-   
+
+/* Max acceptable OCSP response size (DER-encoded responses are typically <2 KiB) */
+#define MD_OCSP_MAX_RESPONSE_LEN    (64 * 1024)
+/* Timeout for OCSP responses */
+#define MD_OCSP_DEFAULT_TIMEOUT apr_time_from_sec(60)
+/* Timeout for connecting to OCSP servers */
+#define MD_OCSP_CONNECT_TIMEOUT apr_time_from_sec(30)
+/*
+ * Below this throughput in bytes per second an OCSP response is regarded as
+ * stalled.
+ */
+#define MD_OCSP_STALLING_BYTES 10
+/* Maximum duration for a stalled period during an OCSP response */
+#define MD_OCSP_STALLING_TIME apr_time_from_sec(30)
+
 struct md_ocsp_reg_t {
     apr_pool_t *p;
     md_store_t *store;
@@ -901,6 +915,12 @@ void md_ocsp_renew(md_ocsp_reg_t *reg, apr_pool_t *p, apr_pool_t *ptemp, apr_tim
     
     rv = md_http_create(&http, ptemp, reg->user_agent, reg->proxy_url);
     if (APR_SUCCESS != rv) goto cleanup;
+
+    md_http_set_response_limit(http, MD_OCSP_MAX_RESPONSE_LEN);
+    md_http_set_timeout_default(http, MD_OCSP_DEFAULT_TIMEOUT);
+    md_http_set_connect_timeout_default(http, MD_OCSP_CONNECT_TIMEOUT);
+    md_http_set_stalling_default(http, MD_OCSP_STALLING_BYTES,
+                                 MD_OCSP_STALLING_TIME);
     
     rv = md_http_multi_perform(http, next_todo, &ctx);
 

~~~

Source file missing in Focal.

## CVE-2026-43951.patch

Previous result: skipped

Touched paths: modules/http/http_filters.c, modules/http2/h2_c2_filter.c

### Dry run fuzz=0 exit=1

~~~text
checking file modules/http/http_filters.c
Hunk #1 FAILED at 1386.
1 out of 1 hunk FAILED
checking file modules/http2/h2_c2_filter.c

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file modules/http/http_filters.c
Hunk #1 FAILED at 1386.
1 out of 1 hunk FAILED
checking file modules/http2/h2_c2_filter.c

~~~

### Dry run fuzz=2 exit=0

~~~text
checking file modules/http/http_filters.c
Hunk #1 succeeded at 1481 with fuzz 2 (offset 95 lines).
checking file modules/http2/h2_c2_filter.c

~~~

### modules/http/http_filters.c

~~~diff
--- a/modules/http/http_filters.c
+++ b/modules/http/http_filters.c
@@ -1386,10 +1386,10 @@ static void merge_response_headers(reque
     if (!apr_is_empty_array(r->content_languages)) {
         int i;
         char *token;
-        char **languages = (char **)(r->content_languages->elts);
         const char *field = apr_table_get(r->headers_out, "Content-Language");
 
         while (field && (token = ap_get_list_item(r->pool, &field)) != NULL) {
+            char **languages = (char **)(r->content_languages->elts);
             for (i = 0; i < r->content_languages->nelts; ++i) {
                 if (!ap_cstr_casecmp(token, languages[i]))
                     break;

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 1378..1409
1378          * empty body (EOS only).
1379          */
1380         if (!check_headers_recursion(r)) {
1381             ap_die(HTTP_INTERNAL_SERVER_ERROR, r);
1382             return AP_FILTER_ERROR;
1383         }
1384         r->status = HTTP_INTERNAL_SERVER_ERROR;
1385         e = ap_bucket_eoc_create(c->bucket_alloc);
1386         APR_BRIGADE_INSERT_TAIL(b, e);
1387         e = apr_bucket_eos_create(c->bucket_alloc);
1388         APR_BRIGADE_INSERT_TAIL(b, e);
1389         ap_set_content_length(r, 0);
1390         recursive_error = 1;
1391     }
1392     else if (eb) {
1393         int status;
1394         status = eb->status;
1395         apr_brigade_cleanup(b);
1396         ap_die(status, r);
1397         return AP_FILTER_ERROR;
1398     }
1399 
1400     if (r->assbackwards) {
1401         r->sent_bodyct = 1;
1402         ap_remove_output_filter(f);
1403         rv = ap_pass_brigade(f->next, b);
1404         goto out;
1405     }
1406 
1407     /*
1408      * Now that we are ready to send a response, we need to combine the two
1409      * header field tables into a single table.  If we don't do this, our
~~~

### modules/http2/h2_c2_filter.c

~~~diff
--- a/modules/http2/h2_c2_filter.c
+++ b/modules/http2/h2_c2_filter.c
@@ -307,10 +307,10 @@ static h2_headers *create_response(reque
     if (!apr_is_empty_array(r->content_languages)) {
         int i;
         char *token;
-        char **languages = (char **)(r->content_languages->elts);
         const char *field = apr_table_get(r->headers_out, "Content-Language");
 
         while (field && (token = ap_get_list_item(r->pool, &field)) != NULL) {
+            char **languages = (char **)(r->content_languages->elts);
             for (i = 0; i < r->content_languages->nelts; ++i) {
                 if (!apr_strnatcasecmp(token, languages[i]))
                     break;

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 299..330
299         apr_table_setn(r->headers_out, "Content-Type", ctype);
300     }
301 
302     if (r->content_encoding) {
303         apr_table_setn(r->headers_out, "Content-Encoding",
304                        r->content_encoding);
305     }
306 
307     if (!apr_is_empty_array(r->content_languages)) {
308         int i;
309         char *token;
310         char **languages = (char **)(r->content_languages->elts);
311         const char *field = apr_table_get(r->headers_out, "Content-Language");
312 
313         while (field && (token = ap_get_list_item(r->pool, &field)) != NULL) {
314             for (i = 0; i < r->content_languages->nelts; ++i) {
315                 if (!apr_strnatcasecmp(token, languages[i]))
316                     break;
317             }
318             if (i == r->content_languages->nelts) {
319                 *((char **) apr_array_push(r->content_languages)) = token;
320             }
321         }
322 
323         field = apr_array_pstrcat(r->pool, r->content_languages, ',');
324         apr_table_setn(r->headers_out, "Content-Language", field);
325     }
326 
327     /*
328      * Control cachability for non-cachable responses if not already set by
329      * some other part of the server configuration.
330      */
~~~

## CVE-2026-44631.patch

Previous result: skipped

Touched paths: include/ap_regex.h, modules/proxy/mod_proxy.c, server/core.c, server/util_pcre.c

### Dry run fuzz=0 exit=1

~~~text
checking file include/ap_regex.h
Hunk #1 FAILED at 189.
1 out of 1 hunk FAILED
checking file modules/proxy/mod_proxy.c
Hunk #1 succeeded at 2580 (offset -344 lines).
checking file server/core.c
Hunk #1 succeeded at 2413 (offset -100 lines).
Hunk #2 succeeded at 2496 (offset -100 lines).
Hunk #3 succeeded at 2585 (offset -100 lines).
checking file server/util_pcre.c
Hunk #1 succeeded at 321 (offset -5 lines).

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file include/ap_regex.h
Hunk #1 FAILED at 189.
1 out of 1 hunk FAILED
checking file modules/proxy/mod_proxy.c
Hunk #1 succeeded at 2580 (offset -344 lines).
checking file server/core.c
Hunk #1 succeeded at 2413 (offset -100 lines).
Hunk #2 succeeded at 2496 (offset -100 lines).
Hunk #3 succeeded at 2585 (offset -100 lines).
checking file server/util_pcre.c
Hunk #1 succeeded at 321 (offset -5 lines).

~~~

### Dry run fuzz=2 exit=0

~~~text
checking file include/ap_regex.h
Hunk #1 succeeded at 187 with fuzz 2 (offset -2 lines).
checking file modules/proxy/mod_proxy.c
Hunk #1 succeeded at 2580 (offset -344 lines).
checking file server/core.c
Hunk #1 succeeded at 2413 (offset -100 lines).
Hunk #2 succeeded at 2496 (offset -100 lines).
Hunk #3 succeeded at 2585 (offset -100 lines).
checking file server/util_pcre.c
Hunk #1 succeeded at 321 (offset -5 lines).

~~~

### include/ap_regex.h

~~~diff
--- a/include/ap_regex.h
+++ b/include/ap_regex.h
@@ -189,6 +189,8 @@ AP_DECLARE(apr_size_t) ap_regerror(int e
  * @param prefix An optional prefix to add to the returned names.  AP_REG_MATCH
  * is the recommended prefix.
  * @param upper If non zero, uppercase the names
+ * @return number of regex backrefernces returned, -1 for error
+ *         for successful match, AP_REG_NOMATCH otherwise
  */
 AP_DECLARE(int) ap_regname(const ap_regex_t *preg,
                            apr_array_header_t *names, const char *prefix,

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 181..212
181  */
182 AP_DECLARE(apr_size_t) ap_regerror(int errcode, const ap_regex_t *preg,
183                                    char *errbuf, apr_size_t errbuf_size);
184 
185 /**
186  * Return an array of named regex backreferences
187  * @param preg The precompiled regex
188  * @param names The array to which the names will be added
189  * @param upper If non zero, uppercase the names
190  */
191 AP_DECLARE(int) ap_regname(const ap_regex_t *preg,
192                            apr_array_header_t *names, const char *prefix,
193                            int upper);
194 
195 /** Destroy a pre-compiled regex.
196  * @param preg The pre-compiled regex to free.
197  */
198 AP_DECLARE(void) ap_regfree(ap_regex_t *preg);
199 
200 /* ap_rxplus: higher-level regexps */
201 
202 typedef struct {
203     ap_regex_t rx;
204     apr_uint32_t flags;
205     const char *subs;
206     const char *match;
207     apr_size_t nmatch;
208     ap_regmatch_t *pmatch;
209 } ap_rxplus_t;
210 
211 /**
212  * Compile a pattern into a regexp.
~~~

### modules/proxy/mod_proxy.c

~~~diff
--- a/modules/proxy/mod_proxy.c
+++ b/modules/proxy/mod_proxy.c
@@ -2924,7 +2924,9 @@ static const char *proxysection(cmd_parm
 
     if (r) {
         conf->refs = apr_array_make(cmd->pool, 8, sizeof(char *));
-        ap_regname(r, conf->refs, AP_REG_MATCH, 1);
+        if (ap_regname(r, conf->refs, AP_REG_MATCH, 1) < 0) {
+            return "Error processing regex captures";
+        }
     }
 
     ap_add_per_proxy_conf(cmd->server, new_dir_conf);

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 2916..2947
2916                            (*worker)->s->busy);
2917                 ap_rputs(apr_strfsize((*worker)->s->transferred, fbuf), r);
2918                 ap_rputs("</td><td>", r);
2919                 ap_rputs(apr_strfsize((*worker)->s->read, fbuf), r);
2920                 ap_rputs("</td>\n", r);
2921 
2922                 /* TODO: Add the rest of dynamic worker data */
2923                 ap_rputs("</tr>\n", r);
2924             }
2925             else {
2926                 ap_rprintf(r, "ProxyBalancer[%d]Worker[%d]Name: %s\n",
2927                            i, n, (*worker)->s->name);
2928                 ap_rprintf(r, "ProxyBalancer[%d]Worker[%d]Status: %s\n",
2929                            i, n, ap_proxy_parse_wstatus(r->pool, *worker));
2930                 ap_rprintf(r, "ProxyBalancer[%d]Worker[%d]Elected: %"
2931                               APR_SIZE_T_FMT "\n",
2932                            i, n, (*worker)->s->elected);
2933                 ap_rprintf(r, "ProxyBalancer[%d]Worker[%d]Busy: %"
2934                               APR_SIZE_T_FMT "\n",
2935                            i, n, (*worker)->s->busy);
2936                 ap_rprintf(r, "ProxyBalancer[%d]Worker[%d]Sent: %"
2937                               APR_OFF_T_FMT "K\n",
2938                            i, n, (*worker)->s->transferred >> 10);
2939                 ap_rprintf(r, "ProxyBalancer[%d]Worker[%d]Rcvd: %"
2940                               APR_OFF_T_FMT "K\n",
2941                            i, n, (*worker)->s->read >> 10);
2942 
2943                 /* TODO: Add the rest of dynamic worker data */
2944             }
2945 
2946             ++worker;
2947         }
~~~

### server/core.c

~~~diff
--- a/server/core.c
+++ b/server/core.c
@@ -2513,7 +2513,9 @@ static const char *dirsection(cmd_parms
 
     if (r) {
         conf->refs = apr_array_make(cmd->pool, 8, sizeof(char *));
-        ap_regname(r, conf->refs, AP_REG_MATCH, 1);
+        if (ap_regname(r, conf->refs, AP_REG_MATCH, 1) < 0) {
+            return "Error processing regex captures";
+        }
     }
 
     /* Make this explicit - the "/" root has 0 elements, that is, we
@@ -2594,7 +2596,9 @@ static const char *urlsection(cmd_parms
 
     if (r) {
         conf->refs = apr_array_make(cmd->pool, 8, sizeof(char *));
-        ap_regname(r, conf->refs, AP_REG_MATCH, 1);
+        if (ap_regname(r, conf->refs, AP_REG_MATCH, 1) < 0) {
+            return "Error processing regex captures";
+        }
     }
 
     ap_add_per_url_conf(cmd->server, new_url_conf);
@@ -2681,7 +2685,9 @@ static const char *filesection(cmd_parms
 
     if (r) {
         conf->refs = apr_array_make(cmd->pool, 8, sizeof(char *));
-        ap_regname(r, conf->refs, AP_REG_MATCH, 1);
+        if (ap_regname(r, conf->refs, AP_REG_MATCH, 1) < 0) {
+            return "Error processing regex captures";
+        }
     }
 
     ap_add_file_conf(cmd->pool, (core_dir_config *)mconfig, new_file_conf);

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 2505..2536
2505     }
2506 
2507     cmd->path = old_path;
2508     cmd->override = old_overrides;
2509 
2510     return NULL;
2511 }
2512 
2513 static const char *filesection(cmd_parms *cmd, void *mconfig, const char *arg)
2514 {
2515     const char *errmsg;
2516     const char *endp = ap_strrchr_c(arg, '>');
2517     int old_overrides = cmd->override;
2518     char *old_path = cmd->path;
2519     core_dir_config *conf;
2520     ap_regex_t *r = NULL;
2521     const command_rec *thiscmd = cmd->cmd;
2522     ap_conf_vector_t *new_file_conf = ap_create_per_dir_config(cmd->pool);
2523     const char *err = ap_check_cmd_context(cmd,
2524                                            NOT_IN_LOCATION | NOT_IN_LIMIT);
2525 
2526     if (err != NULL) {
2527         return err;
2528     }
2529 
2530     if (endp == NULL) {
2531         return unclosed_directive(cmd);
2532     }
2533 
2534     arg = apr_pstrndup(cmd->temp_pool, arg, endp - arg);
2535 
2536     if (!arg[0]) {

Focal lines 2586..2617
2586 
2587     ap_add_file_conf(cmd->pool, (core_dir_config *)mconfig, new_file_conf);
2588 
2589     if (*arg != '\0') {
2590         return apr_pstrcat(cmd->pool, "Multiple ", thiscmd->name,
2591                            "> arguments not (yet) supported.", NULL);
2592     }
2593 
2594     cmd->path = old_path;
2595     cmd->override = old_overrides;
2596 
2597     return NULL;
2598 }
2599 
2600 #define COND_IF      ((void *)1)
2601 #define COND_ELSE    ((void *)2)
2602 #define COND_ELSEIF  ((void *)3)
2603 
2604 static const char *ifsection(cmd_parms *cmd, void *mconfig, const char *arg)
2605 {
2606     const char *errmsg;
2607     const char *endp = ap_strrchr_c(arg, '>');
2608     int old_overrides = cmd->override;
2609     char *old_path = cmd->path;
2610     core_dir_config *conf;
2611     const command_rec *thiscmd = cmd->cmd;
2612     ap_conf_vector_t *new_if_conf = ap_create_per_dir_config(cmd->pool);
2613     const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
2614     const char *condition;
2615     const char *expr_err;
2616 
2617     if (err != NULL) {

Focal lines 2673..2704
2673     if (errmsg != NULL)
2674         return errmsg;
2675 
2676     if (*arg != '\0') {
2677         return apr_pstrcat(cmd->pool, "Multiple ", thiscmd->name,
2678                            "> arguments not supported.", NULL);
2679     }
2680 
2681     cmd->path = old_path;
2682     cmd->override = old_overrides;
2683 
2684     return NULL;
2685 }
2686 
2687 static module *find_module(server_rec *s, const char *name)
2688 {
2689     module *found = ap_find_linked_module(name);
2690 
2691     /* search prelinked stuff */
2692     if (!found) {
2693         ap_module_symbol_t *current = ap_prelinked_module_symbols;
2694 
2695         for (; current->name; ++current) {
2696             if (!strcmp(current->name, name)) {
2697                 found = current->modp;
2698                 break;
2699             }
2700         }
2701     }
2702 
2703     /* search dynamic stuff */
2704     if (!found) {
~~~

### server/util_pcre.c

~~~diff
--- a/server/util_pcre.c
+++ b/server/util_pcre.c
@@ -326,7 +326,16 @@ AP_DECLARE(int) ap_regname(const ap_rege
 
     for (i = 0; i < namecount; i++) {
         const char *offset = nametable + i * nameentrysize;
-        int capture = ((offset[0] << 8) + offset[1]);
+        int capture = (((unsigned char)offset[0] << 8) + (unsigned char)offset[1]);
+        
+        /* Sanity check: reject unreasonably large capture group numbers.
+         * PCRE allows up to 65535 groups, but such large numbers would
+         * cause excessive memory allocation. Limit to a reasonable maximum.
+         */
+        if (capture > 1024) {
+            return -1;
+        }
+        
         while (names->nelts <= capture) {
             apr_array_push(names);
         }

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 318..345
318                        PCRE_INFO_NAMEENTRYSIZE, &nameentrysize);
319     pcre_fullinfo((const pcre *)preg->re_pcre, NULL,
320                        PCRE_INFO_NAMETABLE, &nametable);
321 
322     for (i = 0; i < namecount; i++) {
323         const char *offset = nametable + i * nameentrysize;
324         int capture = ((offset[0] << 8) + offset[1]);
325         while (names->nelts <= capture) {
326             apr_array_push(names);
327         }
328         if (upper || prefix) {
329             char *name = ((char **) names->elts)[capture] =
330                     prefix ? apr_pstrcat(names->pool, prefix, offset + 2,
331                             NULL) :
332                             apr_pstrdup(names->pool, offset + 2);
333             if (upper) {
334                 ap_str_toupper(name);
335             }
336         }
337         else {
338             ((const char **)names->elts)[capture] = offset + 2;
339         }
340     }
341 
342     return namecount;
343 }
344 
345 /* End of pcreposix.c */
~~~

## CVE-2026-48913.patch

Previous result: skipped

Touched paths: modules/http2/h2_c1.c, modules/http2/h2_c1_io.c, modules/http2/h2_c1_io.h, modules/http2/h2_c2.c, modules/http2/h2_c2_filter.c, modules/http2/h2_config.c, modules/http2/h2_config.h, modules/http2/h2_headers.c, modules/http2/h2_mplx.c, modules/http2/h2_mplx.h, modules/http2/h2_proxy_session.c, modules/http2/h2_proxy_util.c, modules/http2/h2_proxy_util.h, modules/http2/h2_request.c, modules/http2/h2_session.c, modules/http2/h2_session.h, modules/http2/h2_stream.c, modules/http2/h2_util.c, modules/http2/h2_util.h, modules/http2/h2_version.h, modules/http2/h2_workers.c, modules/http2/h2_ws.c, modules/http2/h2_ws.h, modules/http2/mod_proxy_http2.c

### Dry run fuzz=0 exit=1

~~~text
checking file modules/http2/h2_c1.c
checking file modules/http2/h2_c1_io.c
Hunk #1 FAILED at 144.
1 out of 4 hunks FAILED
checking file modules/http2/h2_c1_io.h
checking file modules/http2/h2_c2.c
checking file modules/http2/h2_c2_filter.c
Hunk #2 FAILED at 312.
1 out of 2 hunks FAILED
checking file modules/http2/h2_config.c
checking file modules/http2/h2_config.h
checking file modules/http2/h2_headers.c
checking file modules/http2/h2_mplx.c
Hunk #2 succeeded at 412 (offset 14 lines).
Hunk #3 succeeded at 426 (offset 14 lines).
Hunk #4 succeeded at 449 (offset 14 lines).
Hunk #5 succeeded at 895 (offset 15 lines).
Hunk #6 succeeded at 903 (offset 15 lines).
Hunk #7 succeeded at 1004 (offset 15 lines).
Hunk #8 succeeded at 1049 (offset 15 lines).
Hunk #9 succeeded at 1114 (offset 15 lines).
Hunk #10 succeeded at 1145 (offset 15 lines).
Hunk #11 succeeded at 1171 (offset 15 lines).
Hunk #12 succeeded at 1297 (offset 16 lines).
checking file modules/http2/h2_mplx.h
Hunk #1 succeeded at 198 (offset 1 line).
checking file modules/http2/h2_proxy_session.c
checking file modules/http2/h2_proxy_util.c
checking file modules/http2/h2_proxy_util.h
checking file modules/http2/h2_request.c
checking file modules/http2/h2_session.c
Hunk #6 succeeded at 598 (offset 3 lines).
Hunk #7 succeeded at 634 (offset 3 lines).
Hunk #8 succeeded at 733 (offset 3 lines).
Hunk #9 succeeded at 963 (offset 3 lines).
Hunk #10 succeeded at 1032 (offset 3 lines).
Hunk #11 succeeded at 1059 (offset 3 lines).
Hunk #12 succeeded at 1176 (offset 3 lines).
Hunk #13 succeeded at 1555 (offset 3 lines).
Hunk #14 succeeded at 1607 (offset 3 lines).
Hunk #15 succeeded at 1657 (offset 3 lines).
Hunk #16 succeeded at 1817 (offset 8 lines).
Hunk #17 succeeded at 1835 (offset 8 lines).
Hunk #18 succeeded at 1898 (offset 8 lines).
Hunk #19 succeeded at 1969 (offset 8 lines).
Hunk #20 succeeded at 2012 (offset 8 lines).
Hunk #21 succeeded at 2032 (offset 8 lines).
Hunk #22 succeeded at 2082 (offset 8 lines).
checking file modules/http2/h2_session.h
checking file modules/http2/h2_stream.c
checking file modules/http2/h2_util.c
checking file modules/http2/h2_util.h
checking file modules/http2/h2_version.h
checking file modules/http2/h2_workers.c
checking file modules/http2/h2_ws.c
checking file modules/http2/h2_ws.h
checking file modules/http2/mod_proxy_http2.c

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file modules/http2/h2_c1.c
checking file modules/http2/h2_c1_io.c
Hunk #1 FAILED at 144.
1 out of 4 hunks FAILED
checking file modules/http2/h2_c1_io.h
checking file modules/http2/h2_c2.c
checking file modules/http2/h2_c2_filter.c
Hunk #2 FAILED at 312.
1 out of 2 hunks FAILED
checking file modules/http2/h2_config.c
checking file modules/http2/h2_config.h
checking file modules/http2/h2_headers.c
checking file modules/http2/h2_mplx.c
Hunk #2 succeeded at 412 (offset 14 lines).
Hunk #3 succeeded at 426 (offset 14 lines).
Hunk #4 succeeded at 449 (offset 14 lines).
Hunk #5 succeeded at 895 (offset 15 lines).
Hunk #6 succeeded at 903 (offset 15 lines).
Hunk #7 succeeded at 1004 (offset 15 lines).
Hunk #8 succeeded at 1049 (offset 15 lines).
Hunk #9 succeeded at 1114 (offset 15 lines).
Hunk #10 succeeded at 1145 (offset 15 lines).
Hunk #11 succeeded at 1171 (offset 15 lines).
Hunk #12 succeeded at 1297 (offset 16 lines).
checking file modules/http2/h2_mplx.h
Hunk #1 succeeded at 198 (offset 1 line).
checking file modules/http2/h2_proxy_session.c
checking file modules/http2/h2_proxy_util.c
checking file modules/http2/h2_proxy_util.h
checking file modules/http2/h2_request.c
checking file modules/http2/h2_session.c
Hunk #6 succeeded at 598 (offset 3 lines).
Hunk #7 succeeded at 634 (offset 3 lines).
Hunk #8 succeeded at 733 (offset 3 lines).
Hunk #9 succeeded at 963 (offset 3 lines).
Hunk #10 succeeded at 1032 (offset 3 lines).
Hunk #11 succeeded at 1059 (offset 3 lines).
Hunk #12 succeeded at 1176 (offset 3 lines).
Hunk #13 succeeded at 1555 (offset 3 lines).
Hunk #14 succeeded at 1607 (offset 3 lines).
Hunk #15 succeeded at 1657 (offset 3 lines).
Hunk #16 succeeded at 1817 (offset 8 lines).
Hunk #17 succeeded at 1835 (offset 8 lines).
Hunk #18 succeeded at 1898 (offset 8 lines).
Hunk #19 succeeded at 1969 (offset 8 lines).
Hunk #20 succeeded at 2012 (offset 8 lines).
Hunk #21 succeeded at 2032 (offset 8 lines).
Hunk #22 succeeded at 2082 (offset 8 lines).
checking file modules/http2/h2_session.h
checking file modules/http2/h2_stream.c
checking file modules/http2/h2_util.c
checking file modules/http2/h2_util.h
checking file modules/http2/h2_version.h
checking file modules/http2/h2_workers.c
checking file modules/http2/h2_ws.c
checking file modules/http2/h2_ws.h
checking file modules/http2/mod_proxy_http2.c

~~~

### Dry run fuzz=2 exit=1

~~~text
checking file modules/http2/h2_c1.c
checking file modules/http2/h2_c1_io.c
Hunk #1 FAILED at 144.
1 out of 4 hunks FAILED
checking file modules/http2/h2_c1_io.h
checking file modules/http2/h2_c2.c
checking file modules/http2/h2_c2_filter.c
Hunk #2 succeeded at 312 with fuzz 2.
checking file modules/http2/h2_config.c
checking file modules/http2/h2_config.h
checking file modules/http2/h2_headers.c
checking file modules/http2/h2_mplx.c
Hunk #2 succeeded at 412 (offset 14 lines).
Hunk #3 succeeded at 426 (offset 14 lines).
Hunk #4 succeeded at 449 (offset 14 lines).
Hunk #5 succeeded at 895 (offset 15 lines).
Hunk #6 succeeded at 903 (offset 15 lines).
Hunk #7 succeeded at 1004 (offset 15 lines).
Hunk #8 succeeded at 1049 (offset 15 lines).
Hunk #9 succeeded at 1114 (offset 15 lines).
Hunk #10 succeeded at 1145 (offset 15 lines).
Hunk #11 succeeded at 1171 (offset 15 lines).
Hunk #12 succeeded at 1297 (offset 16 lines).
checking file modules/http2/h2_mplx.h
Hunk #1 succeeded at 198 (offset 1 line).
checking file modules/http2/h2_proxy_session.c
checking file modules/http2/h2_proxy_util.c
checking file modules/http2/h2_proxy_util.h
checking file modules/http2/h2_request.c
checking file modules/http2/h2_session.c
Hunk #6 succeeded at 598 (offset 3 lines).
Hunk #7 succeeded at 634 (offset 3 lines).
Hunk #8 succeeded at 733 (offset 3 lines).
Hunk #9 succeeded at 963 (offset 3 lines).
Hunk #10 succeeded at 1032 (offset 3 lines).
Hunk #11 succeeded at 1059 (offset 3 lines).
Hunk #12 succeeded at 1176 (offset 3 lines).
Hunk #13 succeeded at 1555 (offset 3 lines).
Hunk #14 succeeded at 1607 (offset 3 lines).
Hunk #15 succeeded at 1657 (offset 3 lines).
Hunk #16 succeeded at 1817 (offset 8 lines).
Hunk #17 succeeded at 1835 (offset 8 lines).
Hunk #18 succeeded at 1898 (offset 8 lines).
Hunk #19 succeeded at 1969 (offset 8 lines).
Hunk #20 succeeded at 2012 (offset 8 lines).
Hunk #21 succeeded at 2032 (offset 8 lines).
Hunk #22 succeeded at 2082 (offset 8 lines).
checking file modules/http2/h2_session.h
checking file modules/http2/h2_stream.c
checking file modules/http2/h2_util.c
checking file modules/http2/h2_util.h
checking file modules/http2/h2_version.h
checking file modules/http2/h2_workers.c
checking file modules/http2/h2_ws.c
checking file modules/http2/h2_ws.h
checking file modules/http2/mod_proxy_http2.c

~~~

### modules/http2/h2_c1.c

~~~diff
--- a/modules/http2/h2_c1.c
+++ b/modules/http2/h2_c1.c
@@ -48,22 +48,27 @@
 static struct h2_workers *workers;
 
 static int async_mpm;
+#ifdef AP_MPMQ_CAN_WAITIO
+static int mpm_can_waitio;
+#endif
 
 APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_in) *h2_c_logio_add_bytes_in;
 APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_out) *h2_c_logio_add_bytes_out;
 
 apr_status_t h2_c1_child_init(apr_pool_t *pool, server_rec *s)
 {
-    apr_status_t status = APR_SUCCESS;
     int minw, maxw;
     apr_time_t idle_limit;
 
-    status = ap_mpm_query(AP_MPMQ_IS_ASYNC, &async_mpm);
-    if (status != APR_SUCCESS) {
+    if (ap_mpm_query(AP_MPMQ_IS_ASYNC, &async_mpm)) {
         /* some MPMs do not implemnent this */
         async_mpm = 0;
-        status = APR_SUCCESS;
     }
+#ifdef AP_MPMQ_CAN_WAITIO
+    if (!async_mpm || ap_mpm_query(AP_MPMQ_CAN_WAITIO, &mpm_can_waitio)) {
+        mpm_can_waitio = 0;
+    }
+#endif
 
     h2_config_init(pool);
 
@@ -113,23 +118,22 @@ cleanup:
     return rv;
 }
 
-apr_status_t h2_c1_run(conn_rec *c)
+int h2_c1_run(conn_rec *c)
 {
     apr_status_t status;
-    int mpm_state = 0;
+    int mpm_state = 0, keepalive = 0;
     h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);
     
     ap_assert(conn_ctx);
     ap_assert(conn_ctx->session);
+    c->clogging_input_filters = 0;
     do {
         if (c->cs) {
-            c->cs->sense = CONN_SENSE_DEFAULT;
             c->cs->state = CONN_STATE_HANDLER;
         }
     
-        status = h2_session_process(conn_ctx->session, async_mpm);
-        
-        if (APR_STATUS_IS_EOF(status)) {
+        status = h2_session_process(conn_ctx->session, async_mpm, &keepalive);
+        if (status != APR_SUCCESS) {
             ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c, 
                           H2_SSSN_LOG(APLOGNO(03045), conn_ctx->session,
                           "process, closing conn"));
@@ -152,24 +156,51 @@ apr_status_t h2_c1_run(conn_rec *c)
             case H2_SESSION_ST_IDLE:
             case H2_SESSION_ST_BUSY:
             case H2_SESSION_ST_WAIT:
-                c->cs->state = CONN_STATE_WRITE_COMPLETION;
-                if (c->cs && !conn_ctx->session->remote.emitted_count) {
-                    /* let the MPM know that we are not done and want
-                     * the Timeout behaviour instead of a KeepAliveTimeout
+                if (keepalive) {
+                    /* Flush then keep-alive */
+                    c->cs->sense = CONN_SENSE_DEFAULT;
+                    c->cs->state = CONN_STATE_WRITE_COMPLETION;
+                }
+                else {
+                    /* Let the MPM know that we are not done and want to wait
+                     * for read using Timeout instead of KeepAliveTimeout.
                      * See PR 63534. 
                      */
                     c->cs->sense = CONN_SENSE_WANT_READ;
+#ifdef AP_MPMQ_CAN_WAITIO
+                    if (mpm_can_waitio) {
+                        /* This tells the MPM to wait for the connection to be
+                         * readable (CONN_SENSE_WANT_READ) within the configured
+                         * Timeout and then come back to the process_connection()
+                         * hooks again when ready.
+                         */
+                        c->cs->state = CONN_STATE_ASYNC_WAITIO;
+                    }
+                    else
+#endif
+                    {
+                        /* This is a compat workaround to do the same using the
+                         * CONN_STATE_WRITE_COMPLETION state but with both
+                         * CONN_SENSE_WANT_READ to wait for readability rather
+                         * than writing and c->clogging_input_filters to force
+                         * reentering the process_connection() hooks from any
+                         * state when ready. This somehow will use Timeout too.
+                         */
+                        c->cs->state = CONN_STATE_WRITE_COMPLETION;
+                        c->clogging_input_filters = 1;
+                    }
                 }
                 break;
+
             case H2_SESSION_ST_CLEANUP:
             case H2_SESSION_ST_DONE:
             default:
                 c->cs->state = CONN_STATE_LINGER;
-            break;
+                break;
         }
     }
 
-    return APR_SUCCESS;
+    return OK;
 }
 
 apr_status_t h2_c1_pre_close(struct h2_conn_ctx_t *ctx, conn_rec *c)
@@ -275,8 +306,7 @@ static int h2_c1_hook_process_connection
          
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 40..71
40 #include "h2_session.h"
41 #include "h2_stream.h"
42 #include "h2_protocol.h"
43 #include "h2_workers.h"
44 #include "h2_c1.h"
45 #include "h2_version.h"
46 #include "h2_util.h"
47 
48 static struct h2_workers *workers;
49 
50 static int async_mpm;
51 
52 APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_in) *h2_c_logio_add_bytes_in;
53 APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_out) *h2_c_logio_add_bytes_out;
54 
55 apr_status_t h2_c1_child_init(apr_pool_t *pool, server_rec *s)
56 {
57     apr_status_t status = APR_SUCCESS;
58     int minw, maxw;
59     apr_time_t idle_limit;
60 
61     status = ap_mpm_query(AP_MPMQ_IS_ASYNC, &async_mpm);
62     if (status != APR_SUCCESS) {
63         /* some MPMs do not implemnent this */
64         async_mpm = 0;
65         status = APR_SUCCESS;
66     }
67 
68     h2_config_init(pool);
69 
70     h2_get_workers_config(s, &minw, &maxw, &idle_limit);
71     workers = h2_workers_create(s, pool, maxw, minw, idle_limit);

Focal lines 105..136
105     h2_conn_ctx_assign_session(ctx, session);
106     /* remove the input filter of mod_reqtimeout, now that the connection
107      * is established and we have switched to h2. reqtimeout has supervised
108      * possibly configured handshake timeouts and needs to get out of the way
109      * now since the rest of its state handling assumes http/1.x to take place. */
110     ap_remove_input_filter_byhandle(c->input_filters, "reqtimeout");
111 
112 cleanup:
113     return rv;
114 }
115 
116 apr_status_t h2_c1_run(conn_rec *c)
117 {
118     apr_status_t status;
119     int mpm_state = 0;
120     h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);
121     
122     ap_assert(conn_ctx);
123     ap_assert(conn_ctx->session);
124     do {
125         if (c->cs) {
126             c->cs->sense = CONN_SENSE_DEFAULT;
127             c->cs->state = CONN_STATE_HANDLER;
128         }
129     
130         status = h2_session_process(conn_ctx->session, async_mpm);
131         
132         if (APR_STATUS_IS_EOF(status)) {
133             ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c, 
134                           H2_SSSN_LOG(APLOGNO(03045), conn_ctx->session,
135                           "process, closing conn"));
136             c->keepalive = AP_CONN_CLOSE;

Focal lines 144..175
144         }
145     } while (!async_mpm
146              && c->keepalive == AP_CONN_KEEPALIVE 
147              && mpm_state != AP_MPMQ_STOPPING);
148 
149     if (c->cs) {
150         switch (conn_ctx->session->state) {
151             case H2_SESSION_ST_INIT:
152             case H2_SESSION_ST_IDLE:
153             case H2_SESSION_ST_BUSY:
154             case H2_SESSION_ST_WAIT:
155                 c->cs->state = CONN_STATE_WRITE_COMPLETION;
156                 if (c->cs && !conn_ctx->session->remote.emitted_count) {
157                     /* let the MPM know that we are not done and want
158                      * the Timeout behaviour instead of a KeepAliveTimeout
159                      * See PR 63534. 
160                      */
161                     c->cs->sense = CONN_SENSE_WANT_READ;
162                 }
163                 break;
164             case H2_SESSION_ST_CLEANUP:
165             case H2_SESSION_ST_DONE:
166             default:
167                 c->cs->state = CONN_STATE_LINGER;
168             break;
169         }
170     }
171 
172     return APR_SUCCESS;
173 }
174 
175 apr_status_t h2_c1_pre_close(struct h2_conn_ctx_t *ctx, conn_rec *c)
~~~

### modules/http2/h2_c1_io.c

~~~diff
--- a/modules/http2/h2_c1_io.c
+++ b/modules/http2/h2_c1_io.c
@@ -144,32 +144,21 @@ apr_status_t h2_c1_io_init(h2_c1_io *io,
 
     io->session = session;
     io->output = apr_brigade_create(c->pool, c->bucket_alloc);
-    io->is_tls = ap_ssl_conn_is_ssl(session->c1);
-    io->buffer_output  = io->is_tls;
     io->flush_threshold = 4 * (apr_size_t)h2_config_sgeti64(session->s, H2_CONF_STREAM_MAX_MEM);
 
-    if (io->buffer_output) {
-        /* This is what we start with, 
-         * see https://issues.apache.org/jira/browse/TS-2503 
-         */
-        io->warmup_size = h2_config_sgeti64(session->s, H2_CONF_TLS_WARMUP_SIZE);
-        io->cooldown_usecs = (h2_config_sgeti(session->s, H2_CONF_TLS_COOLDOWN_SECS)
-                              * APR_USEC_PER_SEC);
-        io->cooldown_usecs = 0;
-        io->write_size = (io->cooldown_usecs > 0?
-                          WRITE_SIZE_INITIAL : WRITE_SIZE_MAX);
-    }
-    else {
-        io->warmup_size = 0;
-        io->cooldown_usecs = 0;
-        io->write_size = 0;
-    }
+    /* This is what we start with,
+     * see https://issues.apache.org/jira/browse/TS-2503
+     */
+    io->warmup_size = h2_config_sgeti64(session->s, H2_CONF_TLS_WARMUP_SIZE);
+    io->cooldown_usecs = (h2_config_sgeti(session->s, H2_CONF_TLS_COOLDOWN_SECS)
+                          * APR_USEC_PER_SEC);
+    io->write_size = (io->cooldown_usecs > 0?
+                      WRITE_SIZE_INITIAL : WRITE_SIZE_MAX);
 
     if (APLOGctrace1(c)) {
         ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, c,
-                      "h2_c1_io(%ld): init, buffering=%d, warmup_size=%ld, "
-                      "cd_secs=%f", c->id, io->buffer_output,
-                      (long)io->warmup_size,
+                      "h2_c1_io(%ld): init, warmup_size=%ld, "
+                      "cd_secs=%f", c->id, (long)io->warmup_size,
                       ((double)io->cooldown_usecs/APR_USEC_PER_SEC));
     }
 
@@ -366,25 +355,19 @@ apr_status_t h2_c1_io_add_data(h2_c1_io
     ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, io->session->c1,
                   "h2_c1_io(%ld): adding %ld data bytes",
                   io->session->c1->id, (long)length);
-    if (io->buffer_output) {
-        while (length > 0) {
-            remain = assure_scratch_space(io);
-            if (remain >= length) {
-                memcpy(io->scratch + io->slen, data, length);
-                io->slen += length;
-                length = 0;
-            }
-            else {
-                memcpy(io->scratch + io->slen, data, remain);
-                io->slen += remain;
-                data += remain;
-                length -= remain;
-            }
+    while (length > 0) {
+        remain = assure_scratch_space(io);
+        if (remain >= length) {
+            memcpy(io->scratch + io->slen, data, length);
+            io->slen += length;
+            length = 0;
+        }
+        else {
+            memcpy(io->scratch + io->slen, data, remain);
+            io->slen += remain;
+            data += remain;
+            length -= remain;
         }
-    }
-    else {
-        status = apr_brigade_write(io->output, NULL, NULL, data, length);
-        io->buffered_len += length;
     }
     return status;
 }
@@ -403,7 +386,7 @@ apr_status_t h2_c1_io_append(h2_c1_io *i
             APR_BUCKET_REMOVE(b);
             APR_BRIGADE_INSERT_TAIL(io->output, b);
         }
-        else if (io->buffer_output) {
+        else {
             apr_size_t remain = assure_scratch_space(io);
             if (b->length > remain) {
                 apr_bucket_split(b, remain);
@@ -423,13 +406,6 @@ apr_status_t h2_c1_io_append(h2_c1_io *i
                 continue;
             }
         }
-        else {
-            /* no buffering, forward buckets setaside on flush */
-            apr_bucket_setaside(b, io->session->c1->pool);
-            APR_BUCKET_REMOVE(b);
-            APR_BRIGADE_INSERT_TAIL(io->output, b);
-            io->buffered_len += b->length;
-        }
     }
 cleanup:
     return rv;

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 136..167
136     if (APLOG_C_IS_LEVEL(c, level)) { \
137         h2_c1_io_bb_log((c), (stream_id), (level), (tag), (bb)); \
138     }
139 
140 
141 apr_status_t h2_c1_io_init(h2_c1_io *io, h2_session *session)
142 {
143     conn_rec *c = session->c1;
144 
145     io->session = session;
146     io->output = apr_brigade_create(c->pool, c->bucket_alloc);
147     io->is_tls = h2_h2_is_tls(session->c1);
148     io->buffer_output  = io->is_tls;
149     io->flush_threshold = 4 * (apr_size_t)h2_config_sgeti64(session->s, H2_CONF_STREAM_MAX_MEM);
150 
151     if (io->buffer_output) {
152         /* This is what we start with, 
153          * see https://issues.apache.org/jira/browse/TS-2503 
154          */
155         io->warmup_size = h2_config_sgeti64(session->s, H2_CONF_TLS_WARMUP_SIZE);
156         io->cooldown_usecs = (h2_config_sgeti(session->s, H2_CONF_TLS_COOLDOWN_SECS)
157                               * APR_USEC_PER_SEC);
158         io->cooldown_usecs = 0;
159         io->write_size = (io->cooldown_usecs > 0?
160                           WRITE_SIZE_INITIAL : WRITE_SIZE_MAX);
161     }
162     else {
163         io->warmup_size = 0;
164         io->cooldown_usecs = 0;
165         io->write_size = 0;
166     }
167 

Focal lines 358..389
358     return rv;
359 }
360 
361 apr_status_t h2_c1_io_add_data(h2_c1_io *io, const char *data, size_t length)
362 {
363     apr_status_t status = APR_SUCCESS;
364     apr_size_t remain;
365     
366     ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, io->session->c1,
367                   "h2_c1_io(%ld): adding %ld data bytes",
368                   io->session->c1->id, (long)length);
369     if (io->buffer_output) {
370         while (length > 0) {
371             remain = assure_scratch_space(io);
372             if (remain >= length) {
373                 memcpy(io->scratch + io->slen, data, length);
374                 io->slen += length;
375                 length = 0;
376             }
377             else {
378                 memcpy(io->scratch + io->slen, data, remain);
379                 io->slen += remain;
380                 data += remain;
381                 length -= remain;
382             }
383         }
384     }
385     else {
386         status = apr_brigade_write(io->output, NULL, NULL, data, length);
387         io->buffered_len += length;
388     }
389     return status;

Focal lines 395..426
395     apr_status_t rv = APR_SUCCESS;
396 
397     while (!APR_BRIGADE_EMPTY(bb)) {
398         b = APR_BRIGADE_FIRST(bb);
399         if (APR_BUCKET_IS_METADATA(b) || APR_BUCKET_IS_MMAP(b)) {
400             /* need to finish any open scratch bucket, as meta data
401              * needs to be forward "in order". */
402             append_scratch(io);
403             APR_BUCKET_REMOVE(b);
404             APR_BRIGADE_INSERT_TAIL(io->output, b);
405         }
406         else if (io->buffer_output) {
407             apr_size_t remain = assure_scratch_space(io);
408             if (b->length > remain) {
409                 apr_bucket_split(b, remain);
410                 if (io->slen == 0) {
411                     /* complete write_size bucket, append unchanged */
412                     APR_BUCKET_REMOVE(b);
413                     APR_BRIGADE_INSERT_TAIL(io->output, b);
414                     io->buffered_len += b->length;
415                     continue;
416                 }
417             }
418             else {
419                 /* bucket fits in remain, copy to scratch */
420                 rv = read_to_scratch(io, b);
421                 apr_bucket_delete(b);
422                 if (APR_SUCCESS != rv) goto cleanup;
423                 continue;
424             }
425         }
426         else {
~~~

### modules/http2/h2_c1_io.h

~~~diff
--- a/modules/http2/h2_c1_io.h
+++ b/modules/http2/h2_c1_io.h
@@ -30,7 +30,6 @@ typedef struct {
     struct h2_session *session;
     apr_bucket_brigade *output;
 
-    int is_tls;
     int unflushed;
     apr_time_t cooldown_usecs;
     apr_int64_t warmup_size;
@@ -40,7 +39,6 @@ typedef struct {
     apr_int64_t bytes_read;
     apr_int64_t bytes_written;
     
-    int buffer_output;
     apr_off_t buffered_len;
     apr_off_t flush_threshold;
     unsigned int is_flushed : 1;

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 22..53
22 
23 /* h2_io is the basic handler of a httpd connection. It keeps two brigades,
24  * one for input, one for output and works with the installed connection
25  * filters.
26  * The read is done via a callback function, so that input can be processed
27  * directly without copying.
28  */
29 typedef struct {
30     struct h2_session *session;
31     apr_bucket_brigade *output;
32 
33     int is_tls;
34     int unflushed;
35     apr_time_t cooldown_usecs;
36     apr_int64_t warmup_size;
37     
38     apr_size_t write_size;
39     apr_time_t last_write;
40     apr_int64_t bytes_read;
41     apr_int64_t bytes_written;
42     
43     int buffer_output;
44     apr_off_t buffered_len;
45     apr_off_t flush_threshold;
46     unsigned int is_flushed : 1;
47     unsigned int is_passing : 1;
48 
49     char *scratch;
50     apr_size_t ssize;
51     apr_size_t slen;
52 } h2_c1_io;
53 

Focal lines 32..63
32 
33     int is_tls;
34     int unflushed;
35     apr_time_t cooldown_usecs;
36     apr_int64_t warmup_size;
37     
38     apr_size_t write_size;
39     apr_time_t last_write;
40     apr_int64_t bytes_read;
41     apr_int64_t bytes_written;
42     
43     int buffer_output;
44     apr_off_t buffered_len;
45     apr_off_t flush_threshold;
46     unsigned int is_flushed : 1;
47     unsigned int is_passing : 1;
48 
49     char *scratch;
50     apr_size_t ssize;
51     apr_size_t slen;
52 } h2_c1_io;
53 
54 apr_status_t h2_c1_io_init(h2_c1_io *io, struct h2_session *session);
55 
56 /**
57  * Append data to the buffered output.
58  * @param buf the data to append
59  * @param length the length of the data to append
60  */
61 apr_status_t h2_c1_io_add_data(h2_c1_io *io,
62                          const char *buf,
63                          size_t length);
~~~

### modules/http2/h2_c2.c

~~~diff
--- a/modules/http2/h2_c2.c
+++ b/modules/http2/h2_c2.c
@@ -370,6 +370,13 @@ static apr_status_t h2_c2_filter_out(ap_
     h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(f->c);
     apr_status_t rv;
 
+    if (bb == NULL) {
+#if !AP_MODULE_MAGIC_AT_LEAST(20180720, 1)
+        f->c->data_in_output_filters = 0;
+#endif
+        return APR_SUCCESS;
+    }
+
    if (bb == NULL) {
 #if !AP_MODULE_MAGIC_AT_LEAST(20180720, 1)
         f->c->data_in_output_filters = 0;

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 362..393
362     if (APR_STATUS_IS_EAGAIN(rv)) {
363         rv = APR_SUCCESS;
364     }
365     return rv;
366 }
367 
368 static apr_status_t h2_c2_filter_out(ap_filter_t* f, apr_bucket_brigade* bb)
369 {
370     h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(f->c);
371     apr_status_t rv;
372 
373    if (bb == NULL) {
374 #if !AP_MODULE_MAGIC_AT_LEAST(20180720, 1)
375         f->c->data_in_output_filters = 0;
376 #endif
377         return APR_SUCCESS;
378     }
379 
380     ap_assert(conn_ctx);
381 #if AP_HAS_RESPONSE_BUCKETS
382     if (!conn_ctx->has_final_response) {
383         apr_bucket *e;
384 
385         for (e = APR_BRIGADE_FIRST(bb);
386              e != APR_BRIGADE_SENTINEL(bb);
387              e = APR_BUCKET_NEXT(e))
388         {
389             if (AP_BUCKET_IS_RESPONSE(e)) {
390                 ap_bucket_response *resp = e->data;
391                 if (resp->status >= 200) {
392                     conn_ctx->has_final_response = 1;
393                     break;
~~~

### modules/http2/h2_c2_filter.c

~~~diff
--- a/modules/http2/h2_c2_filter.c
+++ b/modules/http2/h2_c2_filter.c
@@ -204,7 +204,7 @@ static int uniq_field_values(void *d, co
          */
         for (i = 0, strpp = (char **) values->elts; i < values->nelts;
              ++i, ++strpp) {
-            if (*strpp && apr_strnatcasecmp(*strpp, start) == 0) {
+            if (*strpp && ap_cstr_casecmp(*strpp, start) == 0) {
                 break;
             }
         }
@@ -312,7 +312,7 @@ static h2_headers *create_response(reque
         while (field && (token = ap_get_list_item(r->pool, &field)) != NULL) {
             char **languages = (char **)(r->content_languages->elts);
             for (i = 0; i < r->content_languages->nelts; ++i) {
-                if (!apr_strnatcasecmp(token, languages[i]))
+                if (!ap_cstr_casecmp(token, languages[i]))
                     break;
             }
             if (i == r->content_languages->nelts) {

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 196..227
196             ++e;
197         }
198         if (*e != '\0') {
199             *e++ = '\0';
200         }
201 
202         /* Now add it to values if it isn't already represented.
203          * Could be replaced by a ap_array_strcasecmp() if we had one.
204          */
205         for (i = 0, strpp = (char **) values->elts; i < values->nelts;
206              ++i, ++strpp) {
207             if (*strpp && apr_strnatcasecmp(*strpp, start) == 0) {
208                 break;
209             }
210         }
211         if (i == values->nelts) {  /* if not found */
212             *(char **)apr_array_push(values) = start;
213         }
214     } while (*e != '\0');
215 
216     return 1;
217 }
218 
219 /*
220  * Since some clients choke violently on multiple Vary fields, or
221  * Vary fields with duplicate tokens, combine any multiples and remove
222  * any duplicates.
223  */
224 static void fix_vary(request_rec *r)
225 {
226     apr_array_header_t *varies;
227 

Focal lines 304..335
304                        r->content_encoding);
305     }
306 
307     if (!apr_is_empty_array(r->content_languages)) {
308         int i;
309         char *token;
310         char **languages = (char **)(r->content_languages->elts);
311         const char *field = apr_table_get(r->headers_out, "Content-Language");
312 
313         while (field && (token = ap_get_list_item(r->pool, &field)) != NULL) {
314             for (i = 0; i < r->content_languages->nelts; ++i) {
315                 if (!apr_strnatcasecmp(token, languages[i]))
316                     break;
317             }
318             if (i == r->content_languages->nelts) {
319                 *((char **) apr_array_push(r->content_languages)) = token;
320             }
321         }
322 
323         field = apr_array_pstrcat(r->pool, r->content_languages, ',');
324         apr_table_setn(r->headers_out, "Content-Language", field);
325     }
326 
327     /*
328      * Control cachability for non-cachable responses if not already set by
329      * some other part of the server configuration.
330      */
331     if (r->no_cache && !apr_table_get(r->headers_out, "Expires")) {
332         char *date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
333         ap_recent_rfc822_date(date, r->request_time);
334         apr_table_add(r->headers_out, "Expires", date);
335     }
~~~

### modules/http2/h2_config.c

~~~diff
--- a/modules/http2/h2_config.c
+++ b/modules/http2/h2_config.c
@@ -77,6 +77,8 @@ typedef struct h2_config {
     int output_buffered;
     apr_interval_time_t stream_timeout;/* beam timeout */
     int max_data_frame_len;          /* max # bytes in a single h2 DATA frame */
+    int max_hd_block_len;            /* max # bytes in a response header block */
+    int max_stream_errors;           /* max # of tolerated stream errors */
     int proxy_requests;              /* act as forward proxy */
     int h2_websockets;               /* if mod_h2 negotiating WebSockets */
 } h2_config;
@@ -104,7 +106,7 @@ static h2_config defconf = {
     1,                      /* modern TLS only */
     -1,                     /* HTTP/1 Upgrade support */
     1024*1024,              /* TLS warmup size */
-    1,                      /* TLS cooldown secs */
+    0,                      /* TLS cooldown secs */
     1,                      /* HTTP/2 server push enabled */
     NULL,                   /* map of content-type to priorities */
     256,                    /* push diary size */
@@ -117,6 +119,8 @@ static h2_config defconf = {
     1,                      /* stream output buffered */
     -1,                     /* beam timeout */
     0,                      /* max DATA frame len, 0 == no extra limit */
+    0,                      /* max header block len, 0 == no extra limit */
+    8,                      /* max stream errors tolerated */
     0,                      /* forward proxy */
     0,                      /* WebSockets negotiation, enabled */
 };
@@ -165,6 +169,8 @@ void *h2_config_create_svr(apr_pool_t *p
     conf->output_buffered      = DEF_VAL;
     conf->stream_timeout       = DEF_VAL;
     conf->max_data_frame_len   = DEF_VAL;
+    conf->max_hd_block_len     = DEF_VAL;
+    conf->max_stream_errors    = DEF_VAL;
     conf->proxy_requests       = DEF_VAL;
     conf->h2_websockets        = DEF_VAL;
     return conf;
@@ -216,6 +222,8 @@ static void *h2_config_merge(apr_pool_t
     n->padding_always       = H2_CONFIG_GET(add, base, padding_always);
     n->stream_timeout       = H2_CONFIG_GET(add, base, stream_timeout);
     n->max_data_frame_len   = H2_CONFIG_GET(add, base, max_data_frame_len);
+    n->max_hd_block_len     = H2_CONFIG_GET(add, base, max_hd_block_len);
+    n->max_stream_errors    = H2_CONFIG_GET(add, base, max_stream_errors);
     n->proxy_requests       = H2_CONFIG_GET(add, base, proxy_requests);
     n->h2_websockets        = H2_CONFIG_GET(add, base, h2_websockets);
     return n;
@@ -313,6 +321,11 @@ static apr_int64_t h2_srv_config_geti64(
             return H2_CONFIG_GET(conf, &defconf, proxy_requests);
         case H2_CONF_WEBSOCKETS:
             return H2_CONFIG_GET(conf, &defconf, h2_websockets);
+        case H2_CONF_MAX_HEADER_BLOCK_LEN:
+            return H2_CONFIG_GET(conf, &defconf, max_hd_block_len);
+        case H2_CONF_MAX_STREAM_ERRORS:
+            return H2_CONFIG_GET(conf, &defconf, max_stream_errors);
+
         default:
             return DEF_VAL;
     }
@@ -381,6 +394,11 @@ static void h2_srv_config_seti(h2_config
         case H2_CONF_WEBSOCKETS:
             H2_CONFIG_SET(conf, h2_websockets, val);
             break;
+        case H2_CONF_MAX_HEADER_BLOCK_LEN:
+            H2_CONFIG_SET(conf, max_hd_block_len, val);
+            break;
+        case H2_CONF_MAX_STREAM_ERRORS:
+            H2_CONFIG_SET(conf, max_stream_errors, val);
         default:
             break;
     }
@@ -650,6 +668,28 @@ static const char *h2_conf_set_max_data_
     return NULL;
 }
 
+static const char *h2_conf_set_max_hd_block_len(cmd_parms *cmd,
+                                                void *dirconf, const char *value)
+{
+    int val = (int)apr_atoi64(value);
+    if (val < 0) {
+        return "value must be 0 or larger";
+    }
+    CONFIG_CMD_SET(cmd, dirconf, H2_CONF_MAX_HEADER_BLOCK_LEN, val);
+    return NULL;
+}
+
+static const char *h2_conf_set_max_stream_errors(cmd_parms *cmd,
+                                               void *dirconf, const char *value)
+{
+    int val = (int)apr_atoi64(value);
+    if (val < 0) {
+        return "value must be 0 or larger";
+    }
+    CONFIG_CMD_SET(cmd, dirconf, H2_CONF_MAX_STREAM_ERRORS, val);
+    return NULL;
+}
+
 static const char *h2_conf_set_session_extra_files(cmd_parms *cmd,
                                                    void *dirconf, const char *value)
 {
@@ -1071,6 +1111,10 @@ const command_rec h2_cmds[] = {
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 69..100
69     
70     int push_diary_size;             /* # of entries in push diary */
71     int copy_files;                  /* if files shall be copied vs setaside on output */
72     apr_array_header_t *push_list;   /* list of h2_push_res configurations */
73     apr_table_t *early_headers;      /* HTTP headers for a 103 response */
74     int early_hints;                 /* support status code 103 */
75     int padding_bits;
76     int padding_always;
77     int output_buffered;
78     apr_interval_time_t stream_timeout;/* beam timeout */
79     int max_data_frame_len;          /* max # bytes in a single h2 DATA frame */
80     int proxy_requests;              /* act as forward proxy */
81     int h2_websockets;               /* if mod_h2 negotiating WebSockets */
82 } h2_config;
83 
84 typedef struct h2_dir_config {
85     const char *name;
86     int h2_upgrade;                  /* Allow HTTP/1 upgrade to h2/h2c */
87     int h2_push;                     /* if HTTP/2 server push is enabled */
88     apr_array_header_t *push_list;   /* list of h2_push_res configurations */
89     apr_table_t *early_headers;      /* HTTP headers for a 103 response */
90     int early_hints;                 /* support status code 103 */
91     apr_interval_time_t stream_timeout;/* beam timeout */
92 } h2_dir_config;
93 
94 
95 static h2_config defconf = {
96     "default",
97     100,                    /* max_streams */
98     H2_INITIAL_WINDOW_SIZE, /* window_size */
99     -1,                     /* min workers */
100     -1,                     /* max workers */

Focal lines 96..127
96     "default",
97     100,                    /* max_streams */
98     H2_INITIAL_WINDOW_SIZE, /* window_size */
99     -1,                     /* min workers */
100     -1,                     /* max workers */
101     apr_time_from_sec(10 * 60), /* workers idle limit */
102     32 * 1024,              /* stream max mem size */
103     -1,                     /* h2 direct mode */
104     1,                      /* modern TLS only */
105     -1,                     /* HTTP/1 Upgrade support */
106     1024*1024,              /* TLS warmup size */
107     1,                      /* TLS cooldown secs */
108     1,                      /* HTTP/2 server push enabled */
109     NULL,                   /* map of content-type to priorities */
110     256,                    /* push diary size */
111     0,                      /* copy files across threads */
112     NULL,                   /* push list */
113     NULL,                   /* early headers */
114     0,                      /* early hints, http status 103 */
115     0,                      /* padding bits */
116     1,                      /* padding always */
117     1,                      /* stream output buffered */
118     -1,                     /* beam timeout */
119     0,                      /* max DATA frame len, 0 == no extra limit */
120     0,                      /* forward proxy */
121     0,                      /* WebSockets negotiation, enabled */
122 };
123 
124 static h2_dir_config defdconf = {
125     "default",
126     -1,                     /* HTTP/1 Upgrade support */
127     -1,                     /* HTTP/2 server push enabled */

Focal lines 109..140
109     NULL,                   /* map of content-type to priorities */
110     256,                    /* push diary size */
111     0,                      /* copy files across threads */
112     NULL,                   /* push list */
113     NULL,                   /* early headers */
114     0,                      /* early hints, http status 103 */
115     0,                      /* padding bits */
116     1,                      /* padding always */
117     1,                      /* stream output buffered */
118     -1,                     /* beam timeout */
119     0,                      /* max DATA frame len, 0 == no extra limit */
120     0,                      /* forward proxy */
121     0,                      /* WebSockets negotiation, enabled */
122 };
123 
124 static h2_dir_config defdconf = {
125     "default",
126     -1,                     /* HTTP/1 Upgrade support */
127     -1,                     /* HTTP/2 server push enabled */
128     NULL,                   /* push list */
129     NULL,                   /* early headers */
130     -1,                     /* early hints, http status 103 */
131     -1,                     /* beam timeout */
132 };
133 
134 void h2_config_init(apr_pool_t *pool)
135 {
136     (void)pool;
137 }
138 
139 void *h2_config_create_svr(apr_pool_t *pool, server_rec *s)
140 {
~~~

### modules/http2/h2_config.h

~~~diff
--- a/modules/http2/h2_config.h
+++ b/modules/http2/h2_config.h
@@ -46,6 +46,8 @@ typedef enum {
     H2_CONF_MAX_DATA_FRAME_LEN,
     H2_CONF_PROXY_REQUESTS,
     H2_CONF_WEBSOCKETS,
+    H2_CONF_MAX_HEADER_BLOCK_LEN,
+    H2_CONF_MAX_STREAM_ERRORS,
 } h2_config_var_t;
 
 struct apr_hash_t;

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 38..69
38     H2_CONF_PUSH,
39     H2_CONF_PUSH_DIARY_SIZE,
40     H2_CONF_COPY_FILES,
41     H2_CONF_EARLY_HINTS,
42     H2_CONF_PADDING_BITS,
43     H2_CONF_PADDING_ALWAYS,
44     H2_CONF_OUTPUT_BUFFER,
45     H2_CONF_STREAM_TIMEOUT,
46     H2_CONF_MAX_DATA_FRAME_LEN,
47     H2_CONF_PROXY_REQUESTS,
48     H2_CONF_WEBSOCKETS,
49 } h2_config_var_t;
50 
51 struct apr_hash_t;
52 struct h2_priority;
53 struct h2_push_res;
54 
55 typedef struct h2_push_res {
56     const char *uri_ref;
57     int critical;
58 } h2_push_res;
59 
60 
61 void *h2_config_create_dir(apr_pool_t *pool, char *x);
62 void *h2_config_merge_dir(apr_pool_t *pool, void *basev, void *addv);
63 void *h2_config_create_svr(apr_pool_t *pool, server_rec *s);
64 void *h2_config_merge_svr(apr_pool_t *pool, void *basev, void *addv);
65 
66 extern const command_rec h2_cmds[];
67 
68 int h2_config_geti(request_rec *r, server_rec *s, h2_config_var_t var);
69 apr_int64_t h2_config_geti64(request_rec *r, server_rec *s, h2_config_var_t var);
~~~

### modules/http2/h2_headers.c

~~~diff
--- a/modules/http2/h2_headers.c
+++ b/modules/http2/h2_headers.c
@@ -90,9 +90,18 @@ h2_headers *h2_bucket_headers_get(apr_bu
     return NULL;
 }
 
+static void bucket_destroy(void *data)
+{
+    h2_bucket_headers *h = data;
+
+    if (apr_bucket_shared_destroy(h)) {
+        apr_bucket_free(h);
+    }
+}
+
 const apr_bucket_type_t h2_bucket_type_headers = {
     "H2HEADERS", 5, APR_BUCKET_METADATA,
-    apr_bucket_destroy_noop,
+    bucket_destroy,
     bucket_read,
     apr_bucket_setaside_noop,
     apr_bucket_split_notimpl,

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 82..113
82     return b;
83 }
84                                        
85 h2_headers *h2_bucket_headers_get(apr_bucket *b)
86 {
87     if (H2_BUCKET_IS_HEADERS(b)) {
88         return ((h2_bucket_headers *)b->data)->headers;
89     }
90     return NULL;
91 }
92 
93 const apr_bucket_type_t h2_bucket_type_headers = {
94     "H2HEADERS", 5, APR_BUCKET_METADATA,
95     apr_bucket_destroy_noop,
96     bucket_read,
97     apr_bucket_setaside_noop,
98     apr_bucket_split_notimpl,
99     apr_bucket_shared_copy
100 };
101 
102 apr_bucket *h2_bucket_headers_clone(apr_bucket *b, apr_pool_t *pool,
103                                     apr_bucket_alloc_t *list)
104 {
105     h2_headers *hdrs = ((h2_bucket_headers *)b->data)->headers;
106     return h2_bucket_headers_create(list, h2_headers_clone(pool, hdrs));
107 }
108 
109 
110 h2_headers *h2_headers_create(int status, const apr_table_t *headers_in, 
111                               const apr_table_t *notes, apr_off_t raw_bytes,
112                               apr_pool_t *pool)
113 {
~~~

### modules/http2/h2_mplx.c

~~~diff
--- a/modules/http2/h2_mplx.c
+++ b/modules/http2/h2_mplx.c
@@ -29,6 +29,7 @@
 #include <http_connection.h>
 #include <http_log.h>
 #include <http_protocol.h>
+#include <scoreboard.h>
 
 #include <mpm_common.h>
 
@@ -397,10 +398,11 @@ apr_status_t h2_mplx_c1_streams_do(h2_mp
 {
     stream_iter_ctx_t x;
     
-    H2_MPLX_ENTER(m);
-
     x.cb = cb;
     x.ctx = ctx;
+
+    H2_MPLX_ENTER(m);
+
     h2_ihash_iter(m->streams, m_stream_iter_wrap, &x);
         
     H2_MPLX_LEAVE(m);
@@ -410,6 +412,7 @@ apr_status_t h2_mplx_c1_streams_do(h2_mp
 typedef struct {
     int stream_count;
     int stream_want_send;
+    int stream_send_win_exhausted;
 } stream_iter_aws_t;
 
 static int m_stream_want_send_data(void *ctx, void *stream)
@@ -432,6 +435,29 @@ int h2_mplx_c1_all_streams_want_send_dat
     return x.stream_count && (x.stream_count == x.stream_want_send);
 }
 
+static int m_stream_send_win_exh(void *ctx, void *s)
+{
+    h2_stream *stream = s;
+    int win;
+    stream_iter_aws_t *x = ctx;
+    ++x->stream_count;
+    win = nghttp2_session_get_stream_remote_window_size(stream->session->ngh2, stream->id);
+    if (win == 0)
+      ++x->stream_send_win_exhausted;
+    return 1;
+}
+
+int h2_mplx_c1_all_streams_send_win_exhausted(h2_mplx *m)
+{
+    stream_iter_aws_t x;
+    x.stream_count = 0;
+    x.stream_send_win_exhausted = 0;
+    H2_MPLX_ENTER(m);
+    h2_ihash_iter(m->streams, m_stream_send_win_exh, &x);
+    H2_MPLX_LEAVE(m);
+    return x.stream_count && (x.stream_count == x.stream_send_win_exhausted);
+}
+
 static int m_report_stream_iter(void *ctx, void *val) {
     h2_mplx *m = ctx;
     h2_stream *stream = val;
@@ -854,9 +880,6 @@ static apr_status_t c2_setup_io(h2_mplx
     memset(&conn_ctx->pipe_in, 0, sizeof(conn_ctx->pipe_in));
     if (stream->input) {
         conn_ctx->beam_in = stream->input;
-        h2_beam_on_send(stream->input, c2_beam_input_write_notify, c2);
-        h2_beam_on_received(stream->input, c2_beam_input_read_notify, c2);
-        h2_beam_on_consumed(stream->input, c1_input_consumed, stream);
 #if H2_USE_PIPES
         action = "create input write pipe";
         rv = apr_file_pipe_create_pools(&conn_ctx->pipe_in[H2_PIPE_OUT],
@@ -865,6 +888,9 @@ static apr_status_t c2_setup_io(h2_mplx
                                         c2->pool, c2->pool);
         if (APR_SUCCESS != rv) goto cleanup;
 #endif
+        h2_beam_on_send(stream->input, c2_beam_input_write_notify, c2);
+        h2_beam_on_received(stream->input, c2_beam_input_read_notify, c2);
+        h2_beam_on_consumed(stream->input, c1_input_consumed, stream);
         h2_beam_on_eagain(stream->input, c2_beam_input_read_eagain, c2);
         if (!h2_beam_empty(stream->input))
             c2_beam_input_write_notify(c2, stream->input);
@@ -963,7 +989,9 @@ static void s_c2_done(h2_mplx *m, conn_r
     /* From here on, the final handling of c2 is done by c1 processing.
      * Which means we can give it c1's scoreboard handle for updates. */
     c2->sbh = m->c1->sbh;
-
+#if AP_MODULE_MAGIC_AT_LEAST(20211221, 29)
+    ap_set_time_process_request(c2->sbh,conn_ctx->started_at,conn_ctx->done_at);
+#endif
     ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c2,
                   "h2_mplx(%s-%d): request done, %f ms elapsed",
                   conn_ctx->id, conn_ctx->stream_id,
@@ -1006,7 +1034,8 @@ static void s_c2_done(h2_mplx *m, conn_r
         int i;
 
         for (i = 0; i < m->spurge->nelts; ++i) {
-            if (stream == APR_ARRAY_IDX(m->spurge, i, h2_stream*)) {
+            stream = APR_ARRAY_IDX(m->spurge, i, h2_stream*);
+            if (stream && (stream->id == conn_ctx->stream_id)) {
                 ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c2,
                               H2_STRM_LOG(APLOGNO(03517), stream, "already in spurge"));
                 ap_assert("stream should not be in spurge" == NULL);
@@ -1070,8 +1099,9 @@ static void s_mplx_be_happy(h2_mplx *m,
             m->last_mood_change = now;
             m->irritations_since = 0;
             ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
-                          H2_MPLX_MSG(m, "mood update, increasing worker limit to %d"),
-                          m->processing_limit);
+                          H2_MPLX_MSG(m, "mood update, increasing worker limit"
+                          "to %d, processing %d right now"),
+                          m->processing_limit, m->processing_count);
         }
     }
 }
@@ -1100,8 +1130,9 @@ static void m_be_annoyed(h2_mplx
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 21..52
21 #include <apr_atomic.h>
22 #include <apr_thread_mutex.h>
23 #include <apr_thread_cond.h>
24 #include <apr_strings.h>
25 #include <apr_time.h>
26 
27 #include <httpd.h>
28 #include <http_core.h>
29 #include <http_connection.h>
30 #include <http_log.h>
31 #include <http_protocol.h>
32 
33 #include <mpm_common.h>
34 
35 #include "mod_http2.h"
36 
37 #include "h2.h"
38 #include "h2_private.h"
39 #include "h2_bucket_beam.h"
40 #include "h2_config.h"
41 #include "h2_c1.h"
42 #include "h2_conn_ctx.h"
43 #include "h2_protocol.h"
44 #include "h2_mplx.h"
45 #include "h2_request.h"
46 #include "h2_stream.h"
47 #include "h2_session.h"
48 #include "h2_c2.h"
49 #include "h2_workers.h"
50 #include "h2_util.h"
51 
52 

Focal lines 389..420
389     H2_MPLX_ENTER(m);
390 
391     max_stream_id_started = m->max_stream_id_started;
392     /* Clear schedule queue, disabling existing streams from starting */ 
393     h2_iq_clear(m->q);
394 
395     H2_MPLX_LEAVE(m);
396     return max_stream_id_started;
397 }
398 
399 typedef struct {
400     h2_mplx_stream_cb *cb;
401     void *ctx;
402 } stream_iter_ctx_t;
403 
404 static int m_stream_iter_wrap(void *ctx, void *stream)
405 {
406     stream_iter_ctx_t *x = ctx;
407     return x->cb(stream, x->ctx);
408 }
409 
410 apr_status_t h2_mplx_c1_streams_do(h2_mplx *m, h2_mplx_stream_cb *cb, void *ctx)
411 {
412     stream_iter_ctx_t x;
413     
414     H2_MPLX_ENTER(m);
415 
416     x.cb = cb;
417     x.ctx = ctx;
418     h2_ihash_iter(m->streams, m_stream_iter_wrap, &x);
419         
420     H2_MPLX_LEAVE(m);

Focal lines 402..433
402 } stream_iter_ctx_t;
403 
404 static int m_stream_iter_wrap(void *ctx, void *stream)
405 {
406     stream_iter_ctx_t *x = ctx;
407     return x->cb(stream, x->ctx);
408 }
409 
410 apr_status_t h2_mplx_c1_streams_do(h2_mplx *m, h2_mplx_stream_cb *cb, void *ctx)
411 {
412     stream_iter_ctx_t x;
413     
414     H2_MPLX_ENTER(m);
415 
416     x.cb = cb;
417     x.ctx = ctx;
418     h2_ihash_iter(m->streams, m_stream_iter_wrap, &x);
419         
420     H2_MPLX_LEAVE(m);
421     return APR_SUCCESS;
422 }
423 
424 typedef struct {
425     int stream_count;
426     int stream_want_send;
427 } stream_iter_aws_t;
428 
429 static int m_stream_want_send_data(void *ctx, void *stream)
430 {
431     stream_iter_aws_t *x = ctx;
432     ++x->stream_count;
433     if (h2_stream_wants_send_data(stream))
~~~

### modules/http2/h2_mplx.h

~~~diff
--- a/modules/http2/h2_mplx.h
+++ b/modules/http2/h2_mplx.h
@@ -197,6 +197,11 @@ apr_status_t h2_mplx_c1_streams_do(h2_mp
 int h2_mplx_c1_all_streams_want_send_data(h2_mplx *m);
 
 /**
+ * Return != 0 iff all open streams have send window exhausted
+ */
+int h2_mplx_c1_all_streams_send_win_exhausted(h2_mplx *m);
+
+/**
  * A stream has been RST_STREAM by the client. Abort
  * any processing going on and remove from processing
  * queue.

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 189..220
189  * @param m the mplx
190  * @param cb the callback to invoke on each stream
191  * @param ctx userdata passed to the callback
192  */
193 apr_status_t h2_mplx_c1_streams_do(h2_mplx *m, h2_mplx_stream_cb *cb, void *ctx);
194 
195 /**
196  * Return != 0 iff all open streams want to send data
197  */
198 int h2_mplx_c1_all_streams_want_send_data(h2_mplx *m);
199 
200 /**
201  * A stream has been RST_STREAM by the client. Abort
202  * any processing going on and remove from processing
203  * queue.
204  */
205 apr_status_t h2_mplx_c1_client_rst(h2_mplx *m, int stream_id,
206                                    struct h2_stream *stream);
207 
208 /**
209  * Get readonly access to a stream for a secondary connection.
210  */
211 const struct h2_stream *h2_mplx_c2_stream_get(h2_mplx *m, int stream_id);
212 
213 /**
214  * A h2 worker asks for a secondary connection to process.
215  * @param out_c2 non-NULL, a pointer where to reveive the next
216  *               secondary connection to process.
217  */
218 apr_status_t h2_mplx_worker_pop_c2(h2_mplx *m, conn_rec **out_c2);
219 
220 
~~~

### modules/http2/h2_proxy_session.c

~~~diff
--- a/modules/http2/h2_proxy_session.c
+++ b/modules/http2/h2_proxy_session.c
@@ -49,6 +49,7 @@ typedef struct h2_proxy_stream {
     unsigned int waiting_on_ping : 1;
     unsigned int headers_ended : 1;
     uint32_t error_code;
+    int proxy_status;
 
     apr_bucket_brigade *input;
     apr_off_t data_sent;
@@ -310,6 +311,15 @@ static int on_frame_recv(nghttp2_session
                     ap_send_interim_response(r, 1);
                 }
             }
+            else if (r->status >= 400) {
+                proxy_dir_conf *dconf;
+                dconf = ap_get_module_config(r->per_dir_config, &proxy_module);
+                if (ap_proxy_should_override(dconf, r->status)) {
+                    apr_table_setn(r->notes, "proxy-error-override", "1");
+                    nghttp2_submit_rst_stream(ngh2, NGHTTP2_FLAG_NONE,
+                          frame->hd.stream_id, NGHTTP2_STREAM_CLOSED);
+                }
+            }
             stream_resume(stream);
             break;
         case NGHTTP2_PING:
@@ -789,7 +799,7 @@ static apr_status_t session_start(h2_pro
     apr_socket_t *s;
     
     s = ap_get_conn_socket(session->c);
-#if (!defined(WIN32) && !defined(NETWARE)) || defined(DOXYGEN)
+#if !defined(WIN32) && !defined(NETWARE)
     if (s) {
         ap_sock_disable_nagle(s);
     }
@@ -856,8 +866,8 @@ static apr_status_t open_stream(h2_proxy
              * Host: header */
             authority = r->server->server_hostname;
             ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(10511)
-                          "HTTP/0.9 request (with no host line) "
-                          "on incoming request and preserve host set "
+                          "incoming HTTP/0.9 request (with no Host header) "
+                          "and preserve host set, "
                           "forcing hostname to be %s for uri %s",
                           authority, r->uri);
             apr_table_setn(r->headers_in, "Host", authority);
@@ -1693,17 +1703,7 @@ static int done_iter(void *udata, void *
     h2_proxy_stream *stream = val;
     int touched = (stream->data_sent || stream->data_received ||
                    stream->id <= ctx->session->last_stream_id);
-    if (touched && stream->output) {
-      apr_bucket *b = ap_bucket_error_create(HTTP_BAD_GATEWAY, NULL,
-                                             stream->r->pool,
-                                             stream->cfront->bucket_alloc);
-      APR_BRIGADE_INSERT_TAIL(stream->output, b);
-      b = apr_bucket_eos_create(stream->cfront->bucket_alloc);
-      APR_BRIGADE_INSERT_TAIL(stream->output, b);
-      ap_pass_brigade(stream->r->output_filters, stream->output);
-    }
-    ctx->done(ctx->session, stream->r, APR_ECONNABORTED, touched,
-              stream->error_code);
+    ctx->done(ctx->session, stream->r, APR_ECONNABORTED, touched, stream->error_code);
     return 1;
 }
 

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 41..72
41     h2_proxy_request *req;
42     const char *real_server_uri;
43     const char *p_server_uri;
44     int standalone;
45 
46     h2_proxy_stream_state_t state;
47     unsigned int suspended : 1;
48     unsigned int waiting_on_100 : 1;
49     unsigned int waiting_on_ping : 1;
50     unsigned int headers_ended : 1;
51     uint32_t error_code;
52 
53     apr_bucket_brigade *input;
54     apr_off_t data_sent;
55     apr_bucket_brigade *output;
56     apr_off_t data_received;
57     
58     apr_table_t *saves;
59 } h2_proxy_stream;
60 
61 
62 static void dispatch_event(h2_proxy_session *session, h2_proxys_event_t ev, 
63                            int arg, const char *msg);
64 static void ping_arrived(h2_proxy_session *session);
65 static apr_status_t check_suspended(h2_proxy_session *session);
66 static void stream_resume(h2_proxy_stream *stream);
67 static apr_status_t submit_trailers(h2_proxy_stream *stream);
68 
69 /*
70  * The H2_PING connection sub-state: a state independant of the H2_SESSION state
71  * of the connection:
72  * - H2_PING_ST_NONE: no interference with request handling, ProxyTimeout in effect.

Focal lines 302..333
302                         r->status_line = ap_get_status_line(r->status);
303                         break;
304                 }
305                 ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03487) 
306                               "h2_proxy_session(%s): got interim HEADERS, "
307                               "status=%d, will forward=%d",
308                               session->id, r->status, forward);
309                 if (forward) {
310                     ap_send_interim_response(r, 1);
311                 }
312             }
313             stream_resume(stream);
314             break;
315         case NGHTTP2_PING:
316             break;
317         case NGHTTP2_PUSH_PROMISE:
318             break;
319         case NGHTTP2_SETTINGS:
320             if (frame->settings.niv > 0) {
321                 n = nghttp2_session_get_remote_settings(ngh2, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
322                 if (n > 0) {
323                     session->remote_max_concurrent = n;
324                 }
325             }
326             break;
327         case NGHTTP2_GOAWAY:
328             /* we expect the remote server to tell us the highest stream id
329              * that it has started processing. */
330             session->last_stream_id = frame->goaway.last_stream_id;
331             dispatch_event(session, H2_PROXYS_EV_REMOTE_GOAWAY, 0, NULL);
332             break;
333         default:

Focal lines 781..812
781     }
782     return p_conn->data;
783 }
784 
785 static apr_status_t session_start(h2_proxy_session *session) 
786 {
787     nghttp2_settings_entry settings[2];
788     int rv, add_conn_window;
789     apr_socket_t *s;
790     
791     s = ap_get_conn_socket(session->c);
792 #if (!defined(WIN32) && !defined(NETWARE)) || defined(DOXYGEN)
793     if (s) {
794         ap_sock_disable_nagle(s);
795     }
796 #endif
797     
798     settings[0].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
799     settings[0].value = 0;
800     settings[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
801     settings[1].value = (1 << session->window_bits_stream) - 1;
802     
803     rv = nghttp2_submit_settings(session->ngh2, NGHTTP2_FLAG_NONE, settings, 
804                                  H2_ALEN(settings));
805     
806     /* If the connection window is larger than our default, trigger a WINDOW_UPDATE */
807     add_conn_window = ((1 << session->window_bits_connection) - 1 -
808                        NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE);
809     if (!rv && add_conn_window != 0) {
810         rv = nghttp2_submit_window_update(session->ngh2, NGHTTP2_FLAG_NONE, 0, add_conn_window);
811     }
812     return rv? APR_EGENERAL : APR_SUCCESS;
~~~

### modules/http2/h2_proxy_util.c

~~~diff
--- a/modules/http2/h2_proxy_util.c
+++ b/modules/http2/h2_proxy_util.c
@@ -34,7 +34,7 @@
 APLOG_USE_MODULE(proxy_http2);
 
 /* h2_log2(n) iff n is a power of 2 */
-unsigned char h2_proxy_log2(int n)
+unsigned char h2_proxy_log2(unsigned int n)
 {
     int lz = 0;
     if (!n) {
@@ -381,7 +381,7 @@ static int iq_bubble_down(h2_proxy_iqueu
  * h2_proxy_ngheader
  ******************************************************************************/
 #define H2_HD_MATCH_LIT_CS(l, name)  \
-    ((strlen(name) == sizeof(l) - 1) && !apr_strnatcasecmp(l, name))
+    ((strlen(name) == sizeof(l) - 1) && !ap_cstr_casecmp(l, name))
 
 static int h2_util_ignore_header(const char *name) 
 {
@@ -500,7 +500,7 @@ static int ignore_header(const literal *
     
     for (i = 0; i < llen; ++i) {
         lit = &lits[i];
-        if (lit->len == nlen && !apr_strnatcasecmp(lit->name, name)) {
+        if (lit->len == nlen && !ap_cstr_casecmp(lit->name, name)) {
             return 1;
         }
     }
@@ -542,7 +542,7 @@ void h2_proxy_util_camel_case_header(cha
 
 /** Match a header value against a string constance, case insensitive */
 #define H2_HD_MATCH_LIT(l, name, nlen)  \
-    ((nlen == sizeof(l) - 1) && !apr_strnatcasecmp(l, name))
+    ((nlen == sizeof(l) - 1) && !ap_cstr_casecmp(l, name))
 
 static apr_status_t h2_headers_add_h1(apr_table_t *headers, apr_pool_t *pool, 
                                       const char *name, size_t nlen,

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 26..57
26 #include <http_request.h>
27 #include <mod_proxy.h>
28 
29 #include <nghttp2/nghttp2.h>
30 
31 #include "h2.h"
32 #include "h2_proxy_util.h"
33 
34 APLOG_USE_MODULE(proxy_http2);
35 
36 /* h2_log2(n) iff n is a power of 2 */
37 unsigned char h2_proxy_log2(int n)
38 {
39     int lz = 0;
40     if (!n) {
41         return 0;
42     }
43     if (!(n & 0xffff0000u)) {
44         lz += 16;
45         n = (n << 16);
46     }
47     if (!(n & 0xff000000u)) {
48         lz += 8;
49         n = (n << 8);
50     }
51     if (!(n & 0xf0000000u)) {
52         lz += 4;
53         n = (n << 4);
54     }
55     if (!(n & 0xc0000000u)) {
56         lz += 2;
57         n = (n << 2);

Focal lines 373..404
373            && (*cmp)(q->elts[i], q->elts[next], ctx) > 0) {
374         iq_swap(q, next, i);
375         i = next;
376     }
377     return i;
378 }
379 
380 /*******************************************************************************
381  * h2_proxy_ngheader
382  ******************************************************************************/
383 #define H2_HD_MATCH_LIT_CS(l, name)  \
384     ((strlen(name) == sizeof(l) - 1) && !apr_strnatcasecmp(l, name))
385 
386 static int h2_util_ignore_header(const char *name) 
387 {
388     /* never forward, ch. 8.1.2.2 */
389     return (H2_HD_MATCH_LIT_CS("connection", name)
390             || H2_HD_MATCH_LIT_CS("proxy-connection", name)
391             || H2_HD_MATCH_LIT_CS("upgrade", name)
392             || H2_HD_MATCH_LIT_CS("keep-alive", name)
393             || H2_HD_MATCH_LIT_CS("transfer-encoding", name));
394 }
395 
396 static int count_header(void *ctx, const char *key, const char *value)
397 {
398     if (!h2_util_ignore_header(key)) {
399         (*((size_t*)ctx))++;
400     }
401     return 1;
402 }
403 
404 #define NV_ADD_LIT_CS(nv, k, v)     add_header(nv, k, sizeof(k) - 1, v, strlen(v))

Focal lines 492..523
492     H2_DEF_LITERAL("alt-svc"),
493 };
494 
495 static int ignore_header(const literal *lits, size_t llen,
496                          const char *name, size_t nlen)
497 {
498     const literal *lit;
499     size_t i;
500     
501     for (i = 0; i < llen; ++i) {
502         lit = &lits[i];
503         if (lit->len == nlen && !apr_strnatcasecmp(lit->name, name)) {
504             return 1;
505         }
506     }
507     return 0;
508 }
509 
510 static int h2_proxy_req_ignore_header(const char *name, size_t len)
511 {
512     return ignore_header(H2_LIT_ARGS(IgnoredRequestHeaders), name, len);
513 }
514 
515 int h2_proxy_res_ignore_header(const char *name, size_t len)
516 {
517     return (h2_proxy_req_ignore_header(name, len) 
518             || ignore_header(H2_LIT_ARGS(IgnoredProxyRespHds), name, len));
519 }
520 
521 void h2_proxy_util_camel_case_header(char *s, size_t len)
522 {
523     size_t start = 1;
~~~

### modules/http2/h2_proxy_util.h

~~~diff
--- a/modules/http2/h2_proxy_util.h
+++ b/modules/http2/h2_proxy_util.h
@@ -150,7 +150,7 @@ int h2_proxy_iq_shift(h2_proxy_iqueue *q
  * common helpers
  ******************************************************************************/
 /* h2_proxy_log2(n) iff n is a power of 2 */
-unsigned char h2_proxy_log2(int n);
+unsigned char h2_proxy_log2(unsigned int n);
 
 /*******************************************************************************
  * HTTP/2 header helpers

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 142..173
142  * The task will be removed.
143  *
144  * @param q the queue to get the first task from
145  * @return the first stream id of the queue, 0 if empty
146  */
147 int h2_proxy_iq_shift(h2_proxy_iqueue *q);
148 
149 /*******************************************************************************
150  * common helpers
151  ******************************************************************************/
152 /* h2_proxy_log2(n) iff n is a power of 2 */
153 unsigned char h2_proxy_log2(int n);
154 
155 /*******************************************************************************
156  * HTTP/2 header helpers
157  ******************************************************************************/
158 void h2_proxy_util_camel_case_header(char *s, size_t len);
159 int h2_proxy_res_ignore_header(const char *name, size_t len);
160 
161 /*******************************************************************************
162  * nghttp2 helpers
163  ******************************************************************************/
164 typedef struct h2_proxy_ngheader {
165     nghttp2_nv *nv;
166     apr_size_t nvlen;
167 } h2_proxy_ngheader;
168 h2_proxy_ngheader *h2_proxy_util_nghd_make_req(apr_pool_t *p, 
169                                                const struct h2_proxy_request *req);
170 
171 h2_proxy_ngheader *h2_proxy_util_nghd_make(apr_pool_t *p, apr_table_t *headers);
172 
173 /*******************************************************************************
~~~

### modules/http2/h2_request.c

~~~diff
--- a/modules/http2/h2_request.c
+++ b/modules/http2/h2_request.c
@@ -122,6 +122,7 @@ apr_status_t h2_request_rcreate(h2_reque
     req->path        = path;
     req->headers     = apr_table_make(pool, 10);
     req->http_status = H2_HTTP_STATUS_UNSET;
+    req->request_time = apr_time_now();
 
     x.pool = pool;
     x.headers = req->headers;

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 114..145
114             }
115         }
116     }
117 
118     req = apr_pcalloc(pool, sizeof(*req));
119     req->method      = apr_pstrdup(pool, r->method);
120     req->scheme      = scheme;
121     req->authority   = authority;
122     req->path        = path;
123     req->headers     = apr_table_make(pool, 10);
124     req->http_status = H2_HTTP_STATUS_UNSET;
125 
126     x.pool = pool;
127     x.headers = req->headers;
128     x.status = APR_SUCCESS;
129     x.scratch = scratch;
130     apr_table_do(set_h1_header, &x, r->headers_in, NULL);
131 
132     *preq = req;
133     return x.status;
134 }
135 
136 apr_status_t h2_request_add_header(h2_request *req, apr_pool_t *pool,
137                                    const char *name, size_t nlen,
138                                    const char *value, size_t vlen,
139                                    struct h2_hd_scratch *scratch,
140                                    int *pwas_added)
141 {
142     apr_status_t status = APR_SUCCESS;
143 
144     *pwas_added = 0;
145     if (nlen <= 0) {
~~~

### modules/http2/h2_session.c

~~~diff
--- a/modules/http2/h2_session.c
+++ b/modules/http2/h2_session.c
@@ -61,6 +61,8 @@ static void transit(h2_session *session,
 static void on_stream_state_enter(void *ctx, h2_stream *stream);
 static void on_stream_state_event(void *ctx, h2_stream *stream, h2_stream_event_t ev);
 static void on_stream_event(void *ctx, h2_stream *stream, h2_stream_event_t ev);
+static apr_status_t h2_session_shutdown(h2_session *session, int error,
+                                        const char *msg, int force_close);
 
 static int h2_session_status_from_apr_status(apr_status_t rv)
 {
@@ -109,31 +111,15 @@ static void cleanup_unprocessed_streams(
     h2_mplx_c1_streams_do(session->mplx, rst_unprocessed_stream, session);
 }
 
-/* APR callback invoked if allocation fails. */
-static int abort_on_oom(int retcode)
-{
-    ap_abort_on_oom();
-    return retcode; /* unreachable, hopefully. */
-}
-
 static h2_stream *h2_session_open_stream(h2_session *session, int stream_id,
                                          int initiated_on)
 {
     h2_stream * stream;
-    apr_allocator_t *allocator;
     apr_pool_t *stream_pool;
-    apr_status_t rv;
-    
-    rv = apr_allocator_create(&allocator);
-    if (rv != APR_SUCCESS)
-      return NULL;
-
-    apr_allocator_max_free_set(allocator, ap_max_mem_free);
-    apr_pool_create_ex(&stream_pool, session->pool, NULL, allocator);
-    apr_allocator_owner_set(allocator, stream_pool);
-    apr_pool_abort_set(abort_on_oom, stream_pool);
+
+    apr_pool_create(&stream_pool, session->pool);
     apr_pool_tag(stream_pool, "h2_stream");
-    
+
     stream = h2_stream_create(stream_id, stream_pool, session, 
                               session->monitor, initiated_on);
     if (stream) {
@@ -290,6 +276,7 @@ static int on_stream_close_cb(nghttp2_se
                           "closing with err=%d %s"), 
                           (int)error_code, h2_protocol_err_description(error_code));
             h2_stream_rst(stream, error_code);
+            h2_mplx_c1_client_rst(session->mplx, stream_id, stream);
         }
     }
     return 0;
@@ -339,9 +326,13 @@ static int on_header_cb(nghttp2_session
         (!stream->rtmp ||
          stream->rtmp->http_status == H2_HTTP_STATUS_UNSET ||
          /* We accept a certain amount of failures in order to reply
-          * with an informative HTTP error response like 413. But if the
-          * client is too wrong, we fail the request a RESET of the stream */
+          * with an informative HTTP error response like 413. But of the
+          * client is too wrong, we RESET the stream */
          stream->request_headers_failed > 100)) {
+        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c1,
+                      H2_SSSN_STRM_MSG(session, frame->hd.stream_id,
+                      "RST stream, header failures: %d"),
+                      (int)stream->request_headers_failed);
         return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
     }
     return 0;
@@ -375,9 +366,11 @@ static int on_frame_recv_cb(nghttp2_sess
         else {
             ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                           H2_SSSN_LOG(APLOGNO(03066), session,
-                          "recv FRAME[%s], frames=%ld/%ld (r/s)"),
+                          "recv FRAME[%s], frames=%ld/%ld (r/s), "
+                          "remote.emitted=%d"),
                           buffer, (long)session->frames_received,
-                         (long)session->frames_sent);
+                         (long)session->frames_sent,
+                         (int)session->remote.emitted_count);
         }
     }
 
@@ -602,7 +595,11 @@ static int on_frame_send_cb(nghttp2_sess
             /* PUSH_PROMISE we report on the promised stream */
             stream_id = frame->push_promise.promised_stream_id;
             break;
-        default:    
+        case NGHTTP2_RST_STREAM:
+            if(frame->rst_stream.error_code == NGHTTP2_FLOW_CONTROL_ERROR)
+              ++session->stream_errors;
+            break;
+        default:
             break;
     }
     
@@ -634,6 +631,30 @@ static int on_frame_send_cb(nghttp2_sess
     return 0;
 }
 
+static int on_frame_not_send_cb(nghttp2_session *ngh2,
+                            const nghttp2_frame *frame,
+                            int ngh2_err,
+                            void *user_data)
+{
+    h2_session *session = user_data;
+    int stream_id = frame->hd.stream_id;
+    h2_stream *stream;
+    char buffer[256];

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 53..84
53 #include "h2_util.h"
54 #include "h2_version.h"
55 #include "h2_workers.h"
56 
57 
58 static void transit(h2_session *session, const char *action,
59                     h2_session_state nstate);
60 
61 static void on_stream_state_enter(void *ctx, h2_stream *stream);
62 static void on_stream_state_event(void *ctx, h2_stream *stream, h2_stream_event_t ev);
63 static void on_stream_event(void *ctx, h2_stream *stream, h2_stream_event_t ev);
64 
65 static int h2_session_status_from_apr_status(apr_status_t rv)
66 {
67     if (rv == APR_SUCCESS) {
68         return NGHTTP2_NO_ERROR;
69     }
70     else if (APR_STATUS_IS_EAGAIN(rv)) {
71         return NGHTTP2_ERR_WOULDBLOCK;
72     }
73     else if (APR_STATUS_IS_EOF(rv)) {
74         return NGHTTP2_ERR_EOF;
75     }
76     return NGHTTP2_ERR_PROTO;
77 }
78 
79 static h2_stream *get_stream(h2_session *session, int stream_id)
80 {
81     return nghttp2_session_get_stream_user_data(session->ngh2, stream_id);
82 }
83 
84 void h2_session_event(h2_session *session, h2_session_event_t ev,

Focal lines 101..132
101         h2_stream_rst(stream, H2_ERR_NO_ERROR);
102         return 0;
103     }
104     return 1;
105 }
106 
107 static void cleanup_unprocessed_streams(h2_session *session)
108 {
109     h2_mplx_c1_streams_do(session->mplx, rst_unprocessed_stream, session);
110 }
111 
112 /* APR callback invoked if allocation fails. */
113 static int abort_on_oom(int retcode)
114 {
115     ap_abort_on_oom();
116     return retcode; /* unreachable, hopefully. */
117 }
118 
119 static h2_stream *h2_session_open_stream(h2_session *session, int stream_id,
120                                          int initiated_on)
121 {
122     h2_stream * stream;
123     apr_allocator_t *allocator;
124     apr_pool_t *stream_pool;
125     apr_status_t rv;
126     
127     rv = apr_allocator_create(&allocator);
128     if (rv != APR_SUCCESS)
129       return NULL;
130 
131     apr_allocator_max_free_set(allocator, ap_max_mem_free);
132     apr_pool_create_ex(&stream_pool, session->pool, NULL, allocator);

Focal lines 282..313
282     h2_stream *stream;
283     
284     (void)ngh2;
285     stream = get_stream(session, stream_id);
286     if (stream && stream->state < H2_SS_CLEANUP) {
287         if (error_code) {
288             ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
289                           H2_STRM_LOG(APLOGNO(03065), stream, 
290                           "closing with err=%d %s"), 
291                           (int)error_code, h2_protocol_err_description(error_code));
292             h2_stream_rst(stream, error_code);
293         }
294     }
295     return 0;
296 }
297 
298 static int on_begin_headers_cb(nghttp2_session *ngh2,
299                                const nghttp2_frame *frame, void *userp)
300 {
301     h2_session *session = (h2_session *)userp;
302     h2_stream *s = NULL;
303     
304     /* We may see HEADERs at the start of a stream or after all DATA
305      * streams to carry trailers. */
306     (void)ngh2;
307     s = get_stream(session, frame->hd.stream_id);
308     if (s) {
309         /* nop */
310     }
311     else if (session->local.accepting) {
312         s = h2_session_open_stream(userp, frame->hd.stream_id, 0);
313     }
~~~

### modules/http2/h2_session.h

~~~diff
--- a/modules/http2/h2_session.h
+++ b/modules/http2/h2_session.h
@@ -60,6 +60,7 @@ typedef enum {
     H2_SESSION_EV_MPM_STOPPING,     /* the process is stopping */
     H2_SESSION_EV_PRE_CLOSE,        /* connection will close after this */
     H2_SESSION_EV_NO_MORE_STREAMS,  /* no more streams to process */
+    H2_SESSION_EV_BAD_CLIENT,       /* client misbehaving badly */
 } h2_session_event_t;
 
 typedef struct h2_session {
@@ -98,7 +99,9 @@ typedef struct h2_session {
     unsigned int pushes_promised;   /* number of http/2 push promises submitted */
     unsigned int pushes_submitted;  /* number of http/2 pushed responses submitted */
     unsigned int pushes_reset;      /* number of http/2 pushed reset by client */
-    
+    unsigned int max_stream_errors; /* max client stream errors tolerated */
+    unsigned int stream_errors;     /* number of stream errors by client */
+
     apr_size_t frames_received;     /* number of http/2 frames received */
     apr_size_t frames_sent;         /* number of http/2 frames sent */
     
@@ -147,8 +150,11 @@ void h2_session_event(h2_session *sessio
  * error occurred.
  *
  * @param session the sessionm to process
+ * @param async if mpm is async
+ * @param pkeepalive on return, != 0 if connection to be put into keepalive
+ *                   behaviour and timouts
  */
-apr_status_t h2_session_process(h2_session *session, int async);
+apr_status_t h2_session_process(h2_session *session, int async, int *pkeepalive);
 
 /**
  * Last chance to do anything before the connection is closed.

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 52..83
52     H2_SESSION_EV_INPUT_PENDING,    /* c1 input may have data pending */
53     H2_SESSION_EV_INPUT_EXHAUSTED,  /* c1 input exhausted */
54     H2_SESSION_EV_LOCAL_GOAWAY,     /* we send a GOAWAY */
55     H2_SESSION_EV_REMOTE_GOAWAY,    /* remote send us a GOAWAY */
56     H2_SESSION_EV_CONN_ERROR,       /* connection error */
57     H2_SESSION_EV_PROTO_ERROR,      /* protocol error */
58     H2_SESSION_EV_CONN_TIMEOUT,     /* connection timeout */
59     H2_SESSION_EV_NGH2_DONE,        /* nghttp2 wants neither read nor write anything */
60     H2_SESSION_EV_MPM_STOPPING,     /* the process is stopping */
61     H2_SESSION_EV_PRE_CLOSE,        /* connection will close after this */
62     H2_SESSION_EV_NO_MORE_STREAMS,  /* no more streams to process */
63 } h2_session_event_t;
64 
65 typedef struct h2_session {
66     int child_num;                  /* child number this session runs in */
67     apr_uint32_t id;                /* identifier of this session, unique per child */
68     conn_rec *c1;                   /* the main connection this session serves */
69     request_rec *r;                 /* the request that started this in case
70                                      * of 'h2c', NULL otherwise */
71     server_rec *s;                  /* server/vhost we're starting on */
72     apr_pool_t *pool;               /* pool to use in session */
73     struct h2_mplx *mplx;           /* multiplexer for stream data */
74     struct h2_workers *workers;     /* for executing streams */
75     struct h2_c1_io_in_ctx_t *cin;  /* connection input filter context */
76     h2_c1_io io;                    /* io on httpd conn filters */
77     unsigned int padding_max;       /* max number of padding bytes */
78     int padding_always;             /* padding has precedence over I/O optimizations */
79     struct nghttp2_session *ngh2;   /* the nghttp2 session (internal use) */
80 
81     h2_session_state state;         /* state session is in */
82     
83     h2_session_props local;         /* properties of local session */

Focal lines 90..121
90     struct h2_push_diary *push_diary; /* remember pushes, avoid duplicates */
91     
92     struct h2_stream_monitor *monitor;/* monitor callbacks for streams */
93     unsigned int open_streams;      /* number of streams processing */
94 
95     unsigned int streams_done;      /* number of http/2 streams handled */
96     unsigned int responses_submitted; /* number of http/2 responses submitted */
97     unsigned int streams_reset;     /* number of http/2 streams reset by client */
98     unsigned int pushes_promised;   /* number of http/2 push promises submitted */
99     unsigned int pushes_submitted;  /* number of http/2 pushed responses submitted */
100     unsigned int pushes_reset;      /* number of http/2 pushed reset by client */
101     
102     apr_size_t frames_received;     /* number of http/2 frames received */
103     apr_size_t frames_sent;         /* number of http/2 frames sent */
104     
105     apr_size_t max_stream_count;    /* max number of open streams */
106     apr_size_t max_stream_mem;      /* max buffer memory for a single stream */
107     apr_size_t max_data_frame_len;  /* max amount of bytes for a single DATA frame */
108 
109     apr_size_t idle_frames;         /* number of rcvd frames that kept session in idle state */
110     apr_interval_time_t idle_delay; /* Time we delay processing rcvd frames in idle state */
111     
112     apr_bucket_brigade *bbtmp;      /* brigade for keeping temporary data */
113 
114     char status[64];                /* status message for scoreboard */
115     int last_status_code;           /* the one already reported */
116     const char *last_status_msg;    /* the one already reported */
117 
118     int input_flushed;              /* stream input was flushed */
119     struct h2_iqueue *out_c1_blocked;  /* all streams with output blocked on c1 buffer full */
120     struct h2_iqueue *ready_to_process;  /* all streams ready for processing */
121 

Focal lines 139..170
139                                conn_rec *c, request_rec *r, server_rec *, 
140                                struct h2_workers *workers);
141 
142 void h2_session_event(h2_session *session, h2_session_event_t ev, 
143                       int err, const char *msg);
144 
145 /**
146  * Process the given HTTP/2 session until it is ended or a fatal
147  * error occurred.
148  *
149  * @param session the sessionm to process
150  */
151 apr_status_t h2_session_process(h2_session *session, int async);
152 
153 /**
154  * Last chance to do anything before the connection is closed.
155  */
156 apr_status_t h2_session_pre_close(h2_session *session, int async);
157 
158 /**
159  * Called when a serious error occurred and the session needs to terminate
160  * without further connection io.
161  * @param session the session to abort
162  * @param reason  the apache status that caused the abort
163  */
164 void h2_session_abort(h2_session *session, apr_status_t reason);
165 
166 /**
167  * Returns if client settings have push enabled.
168  * @param != 0 iff push is enabled in client settings
169  */
170 int h2_session_push_enabled(h2_session *session);
~~~

### modules/http2/h2_stream.c

~~~diff
--- a/modules/http2/h2_stream.c
+++ b/modules/http2/h2_stream.c
@@ -776,6 +776,11 @@ apr_status_t h2_stream_add_header(h2_str
     else if (H2_SS_IDLE == stream->state) {
         int was_added;
         if (!stream->rtmp) {
+            if (H2_STREAM_CLIENT_INITIATED(stream->id)) {
+                ++stream->session->remote.emitted_count;
+              if (stream->id > stream->session->remote.emitted_max)
+                  session->remote.emitted_max = stream->id;
+            }
             stream->rtmp = h2_request_create(stream->id, stream->pool,
                                              NULL, NULL, NULL, NULL, NULL);
         }
@@ -1505,7 +1510,8 @@ static ssize_t stream_data_cb(nghttp2_se
             buf_len = output_data_buffered(stream, &eos, &header_blocked);
         }
         else if (APR_EOF == rv) {
-            if (!stream->output_eos) {
+            if (!stream->output_eos &&
+                !AP_STATUS_IS_HEADER_ONLY(stream->response->status)) {
                 /* Seeing APR_EOF without an EOS bucket received before indicates
                  * that stream output is incomplete. Commonly, we expect to see
                  * an ERROR bucket to have been generated. But faulty handlers
@@ -1613,8 +1619,9 @@ static apr_status_t stream_do_response(h
                 ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c1,
                               H2_STRM_MSG(stream, "process response %d"),
                               resp->status);
-                is_empty = (e != APR_BRIGADE_SENTINEL(stream->out_buffer)
-                            && APR_BUCKET_IS_EOS(e));
+                is_empty = AP_STATUS_IS_HEADER_ONLY(resp->status) ||
+                           ((e != APR_BRIGADE_SENTINEL(stream->out_buffer) &&
+                            APR_BUCKET_IS_EOS(e)));
                 break;
             }
             else if (APR_BUCKET_IS_EOS(b)) {
@@ -1733,10 +1740,10 @@ static apr_status_t stream_do_response(h
     if (nghttp2_is_fatal(ngrv)) {
         rv = APR_EGENERAL;
         h2_session_dispatch_event(stream->session,
-                                 H2_SESSION_EV_PROTO_ERROR, ngrv, nghttp2_strerror(rv));
+                                 H2_SESSION_EV_PROTO_ERROR, ngrv, nghttp2_strerror(ngrv));
         ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c1,
                       APLOGNO(10402) "submit_response: %s",
-                      nghttp2_strerror(rv));
+                      nghttp2_strerror(ngrv));
         goto cleanup;
     }
 

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 768..799
768         }
769     }
770     
771     if (session->s->limit_req_fields > 0 
772         && stream->request_headers_added > session->s->limit_req_fields) {
773         /* already over limit, count this attempt, but do not take it in */
774         ++stream->request_headers_added;
775     }
776     else if (H2_SS_IDLE == stream->state) {
777         int was_added;
778         if (!stream->rtmp) {
779             stream->rtmp = h2_request_create(stream->id, stream->pool,
780                                              NULL, NULL, NULL, NULL, NULL);
781         }
782         status = h2_request_add_header(stream->rtmp, stream->pool,
783                                        name, nlen, value, vlen,
784                                        &session->hd_scratch, &was_added);
785         ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, session->c1,
786                       H2_STRM_MSG(stream, "add_header: '%.*s: %.*s"),
787                       (int)nlen, name, (int)vlen, value);
788         if (was_added) ++stream->request_headers_added;
789     }
790     else if (H2_SS_OPEN == stream->state) {
791         status = add_trailer(stream, name, nlen, value, vlen,
792                              &session->hd_scratch);
793         if (!status) ++stream->request_headers_added;
794     }
795     else {
796         status = APR_EINVAL;
797         goto cleanup;
798     }
799     

Focal lines 1497..1528
1497         ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c1,
1498                       H2_SSSN_STRM_MSG(session, stream_id,
1499                       "buffer_output_received"));
1500         if (APR_STATUS_IS_EAGAIN(rv)) {
1501             /* currently, no more is available */
1502         }
1503         else if (APR_SUCCESS == rv) {
1504             /* got some, re-assess */
1505             buf_len = output_data_buffered(stream, &eos, &header_blocked);
1506         }
1507         else if (APR_EOF == rv) {
1508             if (!stream->output_eos) {
1509                 /* Seeing APR_EOF without an EOS bucket received before indicates
1510                  * that stream output is incomplete. Commonly, we expect to see
1511                  * an ERROR bucket to have been generated. But faulty handlers
1512                  * may not have generated one.
1513                  * We need to RST the stream bc otherwise the client thinks
1514                  * it is all fine. */
1515                  ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c1,
1516                                H2_SSSN_STRM_MSG(session, stream_id, "rst stream"));
1517                  h2_stream_rst(stream, H2_ERR_STREAM_CLOSED);
1518                  return NGHTTP2_ERR_DEFERRED;
1519             }
1520             ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c1,
1521                           H2_SSSN_STRM_MSG(session, stream_id,
1522                           "eof on receive (read len=%ld, %ld in buffer)"),
1523                           (long)length, (long)buf_len);
1524             eos = 1;
1525             rv = APR_SUCCESS;
1526         }
1527         else if (APR_ECONNRESET == rv || APR_ECONNABORTED == rv) {
1528             ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c1,

Focal lines 1605..1636
1605             if (AP_BUCKET_IS_RESPONSE(b)) {
1606                 resp = b->data;
1607 #else /* AP_HAS_RESPONSE_BUCKETS */
1608             if (H2_BUCKET_IS_HEADERS(b)) {
1609                 resp = h2_bucket_headers_get(b);
1610 #endif /* else AP_HAS_RESPONSE_BUCKETS */
1611                 APR_BUCKET_REMOVE(b);
1612                 apr_bucket_destroy(b);
1613                 ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c1,
1614                               H2_STRM_MSG(stream, "process response %d"),
1615                               resp->status);
1616                 is_empty = (e != APR_BRIGADE_SENTINEL(stream->out_buffer)
1617                             && APR_BUCKET_IS_EOS(e));
1618                 break;
1619             }
1620             else if (APR_BUCKET_IS_EOS(b)) {
1621                 h2_stream_rst(stream, H2_ERR_INTERNAL_ERROR);
1622                 rv = APR_EINVAL;
1623                 goto cleanup;
1624             }
1625             else if (AP_BUCKET_IS_ERROR(b)) {
1626                 stream_do_error_bucket(stream, b);
1627                 rv = APR_EINVAL;
1628                 goto cleanup;
1629             }
1630         }
1631         else {
1632             /* data buckets before response headers, an error */
1633             h2_stream_rst(stream, H2_ERR_INTERNAL_ERROR);
1634             rv = APR_EINVAL;
1635             goto cleanup;
1636         }
~~~

### modules/http2/h2_util.c

~~~diff
--- a/modules/http2/h2_util.c
+++ b/modules/http2/h2_util.c
@@ -32,7 +32,7 @@
 #include "h2_util.h"
 
 /* h2_log2(n) iff n is a power of 2 */
-unsigned char h2_log2(int n)
+unsigned char h2_log2(unsigned int n)
 {
     int lz = 0;
     if (!n) {
@@ -1650,7 +1650,7 @@ static int contains_name(const literal *
     for (i = 0; i < llen; ++i) {
         lit = &lits[i];
         if (lit->len == nv->namelen
-            && !ap_cstr_casecmp(lit->name, (const char *)nv->name)) {
+            && !ap_cstr_casecmpn(lit->name, (const char *)nv->name, nv->namelen)) {
             return 1;
         }
     }
@@ -1677,7 +1677,7 @@ int h2_ignore_req_trailer(const char *na
     nghttp2_nv nv;
 
     nv.name = (uint8_t*)name;
-    nv.namelen = strlen(name);
+    nv.namelen = len;
     return (h2_req_ignore_header(&nv)
             || contains_name(H2_LIT_ARGS(IgnoredRequestTrailers), &nv));
 }
@@ -1687,7 +1687,7 @@ int h2_ignore_resp_trailer(const char *n
     nghttp2_nv nv;
 
     nv.name = (uint8_t*)name;
-    nv.namelen = strlen(name);
+    nv.namelen = len;
     return (contains_name(H2_LIT_ARGS(IgnoredResponseHeaders), &nv)
             || contains_name(H2_LIT_ARGS(IgnoredResponseTrailers), &nv));
 }
@@ -1705,7 +1705,7 @@ static apr_status_t req_add_header(apr_t
         return APR_SUCCESS;
     }
     else if (nv->namelen == sizeof("cookie")-1
-             && !ap_cstr_casecmp("cookie", (const char *)nv->name)) {
+             && !ap_cstr_casecmpn("cookie", (const char *)nv->name, nv->namelen)) {
         existing = apr_table_get(headers, "cookie");
         if (existing) {
             if (!nv->valuelen)
@@ -1727,7 +1727,7 @@ static apr_status_t req_add_header(apr_t
         }
     }
     else if (nv->namelen == sizeof("host")-1
-             && !ap_cstr_casecmp("host", (const char *)nv->name)) {
+             && !ap_cstr_casecmpn("host", (const char *)nv->name, nv->namelen)) {
         if (apr_table_get(headers, "Host")) {
             return APR_SUCCESS; /* ignore duplicate */
         }
@@ -1809,9 +1809,11 @@ int h2_util_frame_print(const nghttp2_fr
         }
         case NGHTTP2_RST_STREAM: {
             return apr_snprintf(buffer, maxlen,
-                                "RST_STREAM[length=%d, flags=%d, stream=%d]",
+                                "RST_STREAM[length=%d, flags=%d, stream=%d"
+                                ",error=%d]",
                                 (int)frame->hd.length,
-                                frame->hd.flags, frame->hd.stream_id);
+                                frame->hd.flags, frame->hd.stream_id,
+                                frame->rst_stream.error_code);
         }
         case NGHTTP2_SETTINGS: {
             if (frame->hd.flags & NGHTTP2_FLAG_ACK) {

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 24..55
24 #include <http_log.h>
25 #include <http_protocol.h>
26 #include <http_request.h>
27 
28 #include <nghttp2/nghttp2.h>
29 
30 #include "h2.h"
31 #include "h2_headers.h"
32 #include "h2_util.h"
33 
34 /* h2_log2(n) iff n is a power of 2 */
35 unsigned char h2_log2(int n)
36 {
37     int lz = 0;
38     if (!n) {
39         return 0;
40     }
41     if (!(n & 0xffff0000u)) {
42         lz += 16;
43         n = (n << 16);
44     }
45     if (!(n & 0xff000000u)) {
46         lz += 8;
47         n = (n << 8);
48     }
49     if (!(n & 0xf0000000u)) {
50         lz += 4;
51         n = (n << 4);
52     }
53     if (!(n & 0xc0000000u)) {
54         lz += 2;
55         n = (n << 2);

Focal lines 1642..1673
1642     H2_DEF_LITERAL("proxy-authenticate"),
1643 };
1644 
1645 static int contains_name(const literal *lits, size_t llen, nghttp2_nv *nv)
1646 {
1647     const literal *lit;
1648     size_t i;
1649 
1650     for (i = 0; i < llen; ++i) {
1651         lit = &lits[i];
1652         if (lit->len == nv->namelen
1653             && !ap_cstr_casecmp(lit->name, (const char *)nv->name)) {
1654             return 1;
1655         }
1656     }
1657     return 0;
1658 }
1659 
1660 int h2_util_ignore_resp_header(const char *name)
1661 {
1662     nghttp2_nv nv;
1663 
1664     nv.name = (uint8_t*)name;
1665     nv.namelen = strlen(name);
1666     return contains_name(H2_LIT_ARGS(IgnoredResponseHeaders), &nv);
1667 }
1668 
1669 
1670 static int h2_req_ignore_header(nghttp2_nv *nv)
1671 {
1672     return contains_name(H2_LIT_ARGS(IgnoredRequestHeaders), nv);
1673 }

Focal lines 1669..1700
1669 
1670 static int h2_req_ignore_header(nghttp2_nv *nv)
1671 {
1672     return contains_name(H2_LIT_ARGS(IgnoredRequestHeaders), nv);
1673 }
1674 
1675 int h2_ignore_req_trailer(const char *name, size_t len)
1676 {
1677     nghttp2_nv nv;
1678 
1679     nv.name = (uint8_t*)name;
1680     nv.namelen = strlen(name);
1681     return (h2_req_ignore_header(&nv)
1682             || contains_name(H2_LIT_ARGS(IgnoredRequestTrailers), &nv));
1683 }
1684 
1685 int h2_ignore_resp_trailer(const char *name, size_t len)
1686 {
1687     nghttp2_nv nv;
1688 
1689     nv.name = (uint8_t*)name;
1690     nv.namelen = strlen(name);
1691     return (contains_name(H2_LIT_ARGS(IgnoredResponseHeaders), &nv)
1692             || contains_name(H2_LIT_ARGS(IgnoredResponseTrailers), &nv));
1693 }
1694 
1695 static apr_status_t req_add_header(apr_table_t *headers, apr_pool_t *pool,
1696                                    nghttp2_nv *nv, h2_hd_scratch *scratch,
1697                                    int *pwas_added)
1698 {
1699     const char *existing;
1700 
~~~

### modules/http2/h2_util.h

~~~diff
--- a/modules/http2/h2_util.h
+++ b/modules/http2/h2_util.h
@@ -323,7 +323,7 @@ apr_status_t h2_ififo_remove(h2_ififo *f
  * common helpers
  ******************************************************************************/
 /* h2_log2(n) iff n is a power of 2 */
-unsigned char h2_log2(int n);
+unsigned char h2_log2(unsigned int n);
 
 /**
  * Count the bytes that all key/value pairs in a table have
@@ -337,7 +337,7 @@ apr_size_t h2_util_table_bytes(apr_table
 
 /** Match a header value against a string constance, case insensitive */
 #define H2_HD_MATCH_LIT(l, name, nlen)  \
-    ((nlen == sizeof(l) - 1) && !apr_strnatcasecmp(l, name))
+    ((nlen == sizeof(l) - 1) && !ap_cstr_casecmp(l, name))
 
 /*******************************************************************************
  * HTTP/2 header helpers

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 315..346
315 /**
316  * Remove the integer from the queue, will remove multiple appearances.
317  * @param id  the integer to remove
318  * @return APR_SUCCESS iff > 0 ints were removed, APR_EAGAIN otherwise.
319  */
320 apr_status_t h2_ififo_remove(h2_ififo *fifo, int id);
321 
322 /*******************************************************************************
323  * common helpers
324  ******************************************************************************/
325 /* h2_log2(n) iff n is a power of 2 */
326 unsigned char h2_log2(int n);
327 
328 /**
329  * Count the bytes that all key/value pairs in a table have
330  * in length (exlucding terminating 0s), plus additional extra per pair.
331  *
332  * @param t the table to inspect
333  * @param pair_extra the extra amount to add per pair
334  * @return the number of bytes all key/value pairs have
335  */
336 apr_size_t h2_util_table_bytes(apr_table_t *t, apr_size_t pair_extra);
337 
338 /** Match a header value against a string constance, case insensitive */
339 #define H2_HD_MATCH_LIT(l, name, nlen)  \
340     ((nlen == sizeof(l) - 1) && !apr_strnatcasecmp(l, name))
341 
342 /*******************************************************************************
343  * HTTP/2 header helpers
344  ******************************************************************************/
345 int h2_ignore_req_trailer(const char *name, size_t len);
346 int h2_ignore_resp_trailer(const char *name, size_t len);

Focal lines 329..360
329  * Count the bytes that all key/value pairs in a table have
330  * in length (exlucding terminating 0s), plus additional extra per pair.
331  *
332  * @param t the table to inspect
333  * @param pair_extra the extra amount to add per pair
334  * @return the number of bytes all key/value pairs have
335  */
336 apr_size_t h2_util_table_bytes(apr_table_t *t, apr_size_t pair_extra);
337 
338 /** Match a header value against a string constance, case insensitive */
339 #define H2_HD_MATCH_LIT(l, name, nlen)  \
340     ((nlen == sizeof(l) - 1) && !apr_strnatcasecmp(l, name))
341 
342 /*******************************************************************************
343  * HTTP/2 header helpers
344  ******************************************************************************/
345 int h2_ignore_req_trailer(const char *name, size_t len);
346 int h2_ignore_resp_trailer(const char *name, size_t len);
347 
348 /**
349  * Set the push policy for the given request. Takes request headers into 
350  * account, see draft https://tools.ietf.org/html/draft-ruellan-http-accept-push-policy-00
351  * for details.
352  * 
353  * @param headers the http headers to inspect
354  * @param p the pool to use
355  * @param push_enabled if HTTP/2 server push is generally enabled for this request
356  * @return the push policy desired
357  */
358 int h2_push_policy_determine(apr_table_t *headers, apr_pool_t *p, int push_enabled);
359 
360 /*******************************************************************************
~~~

### modules/http2/h2_version.h

~~~diff
--- a/modules/http2/h2_version.h
+++ b/modules/http2/h2_version.h
@@ -27,7 +27,7 @@
  * @macro
  * Version number of the http2 module as c string
  */
-#define MOD_HTTP2_VERSION "2.0.22"
+#define MOD_HTTP2_VERSION "2.0.42"
 
 /**
  * @macro
@@ -35,7 +35,7 @@
  * release. This is a 24 bit number with 8 bits for major number, 8 bits
  * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
  */
-#define MOD_HTTP2_VERSION_NUM 0x020016
+#define MOD_HTTP2_VERSION_NUM 0x02002a
 
 
 #endif /* mod_h2_h2_version_h */

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 19..41
19 
20 #undef PACKAGE_VERSION
21 #undef PACKAGE_TARNAME
22 #undef PACKAGE_STRING
23 #undef PACKAGE_NAME
24 #undef PACKAGE_BUGREPORT
25 
26 /**
27  * @macro
28  * Version number of the http2 module as c string
29  */
30 #define MOD_HTTP2_VERSION "2.0.22"
31 
32 /**
33  * @macro
34  * Numerical representation of the version number of the http2 module
35  * release. This is a 24 bit number with 8 bits for major number, 8 bits
36  * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
37  */
38 #define MOD_HTTP2_VERSION_NUM 0x020016
39 
40 
41 #endif /* mod_h2_h2_version_h */

Focal lines 27..41
27  * @macro
28  * Version number of the http2 module as c string
29  */
30 #define MOD_HTTP2_VERSION "2.0.22"
31 
32 /**
33  * @macro
34  * Numerical representation of the version number of the http2 module
35  * release. This is a 24 bit number with 8 bits for major number, 8 bits
36  * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
37  */
38 #define MOD_HTTP2_VERSION_NUM 0x020016
39 
40 
41 #endif /* mod_h2_h2_version_h */
~~~

### modules/http2/h2_workers.c

~~~diff
--- a/modules/http2/h2_workers.c
+++ b/modules/http2/h2_workers.c
@@ -131,8 +131,13 @@ static apr_status_t activate_slot(h2_wor
     apr_pool_tag(pool, "h2_worker_slot");
     slot->pool = pool;
 
+#if defined(AP_HAS_THREAD_LOCAL)
+    rv = ap_thread_create(&slot->thread, workers->thread_attr,
+                          slot_run, slot, slot->pool);
+#else
     rv = apr_thread_create(&slot->thread, workers->thread_attr,
                            slot_run, slot, slot->pool);
+#endif
 
 cleanup:
     if (rv != APR_SUCCESS) {

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 123..154
123 
124     slot->state = H2_SLOT_RUN;
125     slot->should_shutdown = 0;
126     slot->is_idle = 0;
127     slot->pool = NULL;
128     ++workers->active_slots;
129     rv = apr_pool_create(&pool, workers->pool);
130     if (APR_SUCCESS != rv) goto cleanup;
131     apr_pool_tag(pool, "h2_worker_slot");
132     slot->pool = pool;
133 
134     rv = apr_thread_create(&slot->thread, workers->thread_attr,
135                            slot_run, slot, slot->pool);
136 
137 cleanup:
138     if (rv != APR_SUCCESS) {
139         AP_DEBUG_ASSERT(0);
140         slot->state = H2_SLOT_FREE;
141         if (slot->pool) {
142             apr_pool_destroy(slot->pool);
143             slot->pool = NULL;
144         }
145         APR_RING_INSERT_TAIL(&workers->free, slot, h2_slot, link);
146         --workers->active_slots;
147     }
148     return rv;
149 }
150 
151 static void join_zombies(h2_workers *workers)
152 {
153     h2_slot *slot;
154     apr_status_t status;
~~~

### modules/http2/h2_ws.c

~~~diff
--- a/modules/http2/h2_ws.c
+++ b/modules/http2/h2_ws.c
@@ -44,7 +44,7 @@
 
 #if H2_USE_WEBSOCKETS
 
-#include "apr_encode.h" /* H2_USE_WEBSOCKETS is conditional on APR 1.6+ */
+#include "apr_encode.h" /* H2_USE_WEBSOCKETS is conditional on APR 1.7+ */
 
 static ap_filter_rec_t *c2_ws_out_filter_handle;
 
@@ -239,7 +239,7 @@ static void ws_handle_resp(conn_rec *c2,
                  * or in the request processings implementation of WebSockets */
                 ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c2, APLOGNO(10463)
                               "h2_c2(%s-%d): websocket CONNECT, 101 response "
-                              "with 'Sec-WebSocket-Accept: %s' but expected %s",
+                              "without 'Sec-WebSocket-Accept: %s' but expected %s",
                               conn_ctx->id, conn_ctx->stream_id, hd,
                               ws_ctx->ws_accept_base64);
             }

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 36..67
36 #include <ap_mpm.h>
37 
38 #include "h2_private.h"
39 #include "h2_config.h"
40 #include "h2_conn_ctx.h"
41 #include "h2_headers.h"
42 #include "h2_request.h"
43 #include "h2_ws.h"
44 
45 #if H2_USE_WEBSOCKETS
46 
47 #include "apr_encode.h" /* H2_USE_WEBSOCKETS is conditional on APR 1.6+ */
48 
49 static ap_filter_rec_t *c2_ws_out_filter_handle;
50 
51 struct ws_filter_ctx {
52     const char *ws_accept_base64;
53     int has_final_response;
54     int override_body;
55 };
56 
57 /**
58  * Generate the "Sec-WebSocket-Accept" header field for the given key
59  * (base64 encoded) as defined in RFC 6455 ch. 4.2.2 step 5.3
60  */
61 static const char *gen_ws_accept(conn_rec *c, const char *key_base64)
62 {
63     apr_byte_t dgst[APR_SHA1_DIGESTSIZE];
64     const char ws_guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
65     apr_sha1_ctx_t sha1_ctx;
66 
67     apr_sha1_init(&sha1_ctx);

Focal lines 231..262
231                 /* This points to someone being confused */
232                 ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c2, APLOGNO(10462)
233                               "h2_c2(%s-%d): websocket CONNECT, got 101 response "
234                               "without Sec-WebSocket-Accept header",
235                               conn_ctx->id, conn_ctx->stream_id);
236             }
237             else {
238                 /* This points to a bug, either in our WebSockets negotiation
239                  * or in the request processings implementation of WebSockets */
240                 ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c2, APLOGNO(10463)
241                               "h2_c2(%s-%d): websocket CONNECT, 101 response "
242                               "with 'Sec-WebSocket-Accept: %s' but expected %s",
243                               conn_ctx->id, conn_ctx->stream_id, hd,
244                               ws_ctx->ws_accept_base64);
245             }
246             b_override = make_invalid_resp(c2, HTTP_BAD_GATEWAY, resp->notes);
247             override_body = is_final = 1;
248         }
249     }
250     else if (resp->status < 200) {
251         /* other intermediate response, pass through */
252     }
253     else if (resp->status < 300) {
254         /* Failure, we might be talking to a plain http resource */
255         ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
256                       "h2_c2(%s-%d): websocket CONNECT, invalid response %d",
257                       conn_ctx->id, conn_ctx->stream_id, resp->status);
258         b_override = make_invalid_resp(c2, HTTP_BAD_GATEWAY, resp->notes);
259         override_body = is_final = 1;
260     }
261     else {
262         /* error response, pass through. */
~~~

### modules/http2/h2_ws.h

~~~diff
--- a/modules/http2/h2_ws.h
+++ b/modules/http2/h2_ws.h
@@ -23,7 +23,7 @@
  * Rewrite a websocket request.
  *
  * @param req the h2 request to rewrite
- * @param c2 the connection to process the request on
+ * @param conn the connection to process the request on
  * @param no_body != 0 iff the request is known to have no body
  * @return the websocket request for internal submit
  */

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 15..35
15  */
16 
17 #ifndef __mod_h2__h2_ws__
18 #define __mod_h2__h2_ws__
19 
20 #include "h2.h"
21 
22 /**
23  * Rewrite a websocket request.
24  *
25  * @param req the h2 request to rewrite
26  * @param c2 the connection to process the request on
27  * @param no_body != 0 iff the request is known to have no body
28  * @return the websocket request for internal submit
29  */
30 const h2_request *h2_ws_rewrite_request(const h2_request *req,
31                                         conn_rec *c2, int no_body);
32 
33 void h2_ws_register_hooks(void);
34 
35 #endif /* defined(__mod_h2__h2_ws__) */
~~~

### modules/http2/mod_proxy_http2.c

~~~diff
--- a/modules/http2/mod_proxy_http2.c
+++ b/modules/http2/mod_proxy_http2.c
@@ -65,7 +65,7 @@ typedef struct h2_proxy_ctx {
     unsigned is_ssl : 1;
     
     request_rec *r;            /* the request processed in this ctx */
-    int r_status;              /* status of request work */
+    apr_status_t r_status;     /* status of request work */
     int r_done;                /* request was processed, not necessarily successfully */
     int r_may_retry;           /* request may be retried */
     int has_reusable_session;  /* http2 session is live and clean */
@@ -239,9 +239,15 @@ static void request_done(h2_proxy_ctx *c
                       ctx->id, touched, error_code);
         ctx->r_done = 1;
         if (touched) ctx->r_may_retry = 0;
-        ctx->r_status = error_code? HTTP_BAD_GATEWAY :
-            ((status == APR_SUCCESS)? OK :
-             ap_map_http_request_error(status, HTTP_SERVICE_UNAVAILABLE));
+        if (apr_table_get(r->notes, "proxy-error-override")) {
+            ctx->r_status = r->status;
+            r->status = OK;
+        }
+        else {
+          ctx->r_status = error_code? HTTP_BAD_GATEWAY :
+              ((status == APR_SUCCESS)? OK :
+               ap_map_http_request_error(status, HTTP_SERVICE_UNAVAILABLE));
+        }
     }
 }    
 
@@ -414,7 +420,7 @@ run_connect:
                       "setup new connection: is_ssl=%d %s %s %s", 
                       ctx->p_conn->is_ssl, ctx->p_conn->ssl_hostname, 
                       locurl, ctx->p_conn->hostname);
-        ctx->r_status = ap_map_http_request_error(status, HTTP_SERVICE_UNAVAILABLE);
+        ctx->r_status = status;
         goto cleanup;
     }
     
@@ -428,7 +434,12 @@ run_connect:
     if (ctx->cfront->aborted) goto cleanup;
     status = ctx_run(ctx);
 
-    if (ctx->r_status != OK && ctx->r_may_retry && !ctx->cfront->aborted) {
+    if (apr_table_get(r->notes, "proxy-error-override")) {
+        /* pass on out */
+        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, ctx->cfront,
+                      "proxy-error-override status %d", ctx->r_status);
+    }
+    else if (ctx->r_status != APR_SUCCESS && ctx->r_may_retry && !ctx->cfront->aborted) {
         /* Not successfully processed, but may retry, tear down old conn and start over */
         if (ctx->p_conn) {
             ctx->p_conn->close = 1;
@@ -463,13 +474,7 @@ cleanup:
 
     ap_set_module_config(ctx->cfront->conn_config, &proxy_http2_module, NULL);
     ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, ctx->cfront,
-                  APLOGNO(03377) "leaving handler");
-    if (ctx->r_status != OK) {
-        ap_die(ctx->r_status, r);
-    }
-    else if (status != APR_SUCCESS) {
-        ap_die(ap_map_http_request_error(status, HTTP_SERVICE_UNAVAILABLE), r);
-    }
+                  APLOGNO(03377) "leaving handler -> %d", ctx->r_status);
     return ctx->r_status;
 }
 

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 57..88
57     char server_portstr[32];
58     proxy_conn_rec *p_conn;
59     proxy_worker *worker;
60     proxy_server_conf *conf;
61     
62     apr_size_t req_buffer_size;
63     int capacity;
64     
65     unsigned is_ssl : 1;
66     
67     request_rec *r;            /* the request processed in this ctx */
68     int r_status;              /* status of request work */
69     int r_done;                /* request was processed, not necessarily successfully */
70     int r_may_retry;           /* request may be retried */
71     int has_reusable_session;  /* http2 session is live and clean */
72 } h2_proxy_ctx;
73 
74 static int h2_proxy_post_config(apr_pool_t *p, apr_pool_t *plog,
75                                 apr_pool_t *ptemp, server_rec *s)
76 {
77     void *data = NULL;
78     const char *init_key = "mod_proxy_http2_init_counter";
79     nghttp2_info *ngh2;
80     apr_status_t status = APR_SUCCESS;
81     (void)plog;(void)ptemp;
82     
83     apr_pool_userdata_get(&data, init_key, s->process->pool);
84     if ( data == NULL ) {
85         apr_pool_userdata_set((const void *)1, init_key,
86                               apr_pool_cleanup_null, s->process->pool);
87         return APR_SUCCESS;
88     }

Focal lines 231..262
231 }
232 
233 static void request_done(h2_proxy_ctx *ctx, request_rec *r,
234                          apr_status_t status, int touched, int error_code)
235 {   
236     if (r == ctx->r) {
237         ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, r->connection, 
238                       "h2_proxy_session(%s): request done, touched=%d, error=%d",
239                       ctx->id, touched, error_code);
240         ctx->r_done = 1;
241         if (touched) ctx->r_may_retry = 0;
242         ctx->r_status = error_code? HTTP_BAD_GATEWAY :
243             ((status == APR_SUCCESS)? OK :
244              ap_map_http_request_error(status, HTTP_SERVICE_UNAVAILABLE));
245     }
246 }    
247 
248 static void session_req_done(h2_proxy_session *session, request_rec *r,
249                              apr_status_t status, int touched, int error_code)
250 {
251     request_done(session->user_data, r, status, touched, error_code);
252 }
253 
254 static apr_status_t ctx_run(h2_proxy_ctx *ctx) {
255     apr_status_t status = OK;
256     h2_proxy_session *session;
257     int h2_front;
258     
259     /* Step Four: Send the Request in a new HTTP/2 stream and
260      * loop until we got the response or encounter errors.
261      */
262     ctx->has_reusable_session = 0; /* don't know yet */

Focal lines 406..437
406                       ctx->p_conn->hostname);
407         goto cleanup;
408     }
409     
410     /* Step Three: Create conn_rec for the socket we have open now. */
411     status = ap_proxy_connection_create_ex(ctx->proxy_func, ctx->p_conn, ctx->r);
412     if (status != OK) {
413         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, ctx->cfront, APLOGNO(03353)
414                       "setup new connection: is_ssl=%d %s %s %s", 
415                       ctx->p_conn->is_ssl, ctx->p_conn->ssl_hostname, 
416                       locurl, ctx->p_conn->hostname);
417         ctx->r_status = ap_map_http_request_error(status, HTTP_SERVICE_UNAVAILABLE);
418         goto cleanup;
419     }
420     
421     if (!ctx->p_conn->data && ctx->is_ssl) {
422         /* New SSL connection: set a note on the connection about what
423          * protocol we need. */
424         apr_table_setn(ctx->p_conn->connection->notes,
425                        "proxy-request-alpn-protos", "h2");
426     }
427 
428     if (ctx->cfront->aborted) goto cleanup;
429     status = ctx_run(ctx);
430 
431     if (ctx->r_status != OK && ctx->r_may_retry && !ctx->cfront->aborted) {
432         /* Not successfully processed, but may retry, tear down old conn and start over */
433         if (ctx->p_conn) {
434             ctx->p_conn->close = 1;
435 #if AP_MODULE_MAGIC_AT_LEAST(20140207, 2)
436             proxy_run_detach_backend(r, ctx->p_conn);
437 #endif
~~~

## CVE-2026-7363X.patch

Previous result: skipped

Touched paths: modules/aaa/config.m4, modules/aaa/mod_auth_digest.c

### Dry run fuzz=0 exit=1

~~~text
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

~~~

### Dry run fuzz=1 exit=1

~~~text
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

~~~

### Dry run fuzz=2 exit=1

~~~text
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

~~~

### modules/aaa/config.m4

~~~diff
--- a/modules/aaa/config.m4
+++ b/modules/aaa/config.m4
@@ -70,9 +70,9 @@ APACHE_MODULE(auth_basic, basic authenti
 APACHE_MODULE(auth_form, form authentication, , , most)
 APACHE_MODULE(auth_digest, RFC2617 Digest authentication, , , most, [
   APR_CHECK_APR_DEFINE(APR_HAS_RANDOM)
-  if test $ac_cv_define_APR_HAS_RANDOM = "no"; then
-    echo "You need APR random support to use mod_auth_digest."
-    echo "Look at APR configure options --with-egd and --with-devrandom."
+  APR_CHECK_APR_DEFINE(APR_HAS_SHARED_MEMORY)
+  if test "${ac_cv_define_APR_HAS_RANDOM}X${ac_cv_define_APR_HAS_SHARED_MEMORY}" != "yesXyes"; then
+    AC_MSG_NOTICE([mod_auth_digest requires APR with random and shared memory support])
     enable_auth_digest="no"
   fi
 ])

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 62..84
62 dnl - host access control compatibility modules. Implements Order, Allow,
63 dnl Deny, Satisfy for backward compatibility.  These directives have been
64 dnl deprecated in 2.4.
65 APACHE_MODULE(access_compat, mod_access compatibility, , , yes)
66 
67 dnl these are the front-end authentication modules
68 
69 APACHE_MODULE(auth_basic, basic authentication, , , yes)
70 APACHE_MODULE(auth_form, form authentication, , , most)
71 APACHE_MODULE(auth_digest, RFC2617 Digest authentication, , , most, [
72   APR_CHECK_APR_DEFINE(APR_HAS_RANDOM)
73   if test $ac_cv_define_APR_HAS_RANDOM = "no"; then
74     echo "You need APR random support to use mod_auth_digest."
75     echo "Look at APR configure options --with-egd and --with-devrandom."
76     enable_auth_digest="no"
77   fi
78 ])
79 
80 APACHE_MODULE(allowmethods, restrict allowed HTTP methods, , , most)
81 
82 APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])
83 
84 APACHE_MODPATH_FINISH
~~~

### modules/aaa/mod_auth_digest.c

~~~diff
--- a/modules/aaa/mod_auth_digest.c
+++ b/modules/aaa/mod_auth_digest.c
@@ -18,7 +18,7 @@
  * mod_auth_digest: MD5 digest authentication
  *
  * Originally by Alexei Kosut <akosut@nueva.pvt.k12.ca.us>
- * Updated to RFC-2617 by Ronald Tschal�r <ronald@innovation.ch>
+ * Updated to RFC-2617 by Ronald Tschalär <ronald@innovation.ch>
  * based on mod_auth, by Rob McCool and Robert S. Thau
  *
  * This module an updated version of modules/standard/mod_digest.c
@@ -29,7 +29,7 @@
  * Open Issues:
  *   - qop=auth-int (when streams and trailer support available)
  *   - nonce-format configurability
- *   - Proxy-Authorization-Info header is set by this module, but is
+ *   - Proxy-Authentication-Info header is set by this module, but is
  *     currently ignored by mod_proxy (needs patch to mod_proxy)
  *   - The source of the secret should be run-time directive (with server
  *     scope: RSRC_CONF)
@@ -56,6 +56,7 @@
 #include "apr_errno.h"
 #include "apr_global_mutex.h"
 #include "apr_strings.h"
+#include "apr_atomic.h"
 
 #define APR_WANT_STRFUNC
 #include "apr_want.h"
@@ -80,17 +81,19 @@
 #include <unistd.h>
 #endif
 
+/* configure declines to build this module without both of these, so this
+ * only catches builds which don't use it. */
+#if !APR_HAS_RANDOM || !APR_HAS_SHARED_MEMORY
+#error mod_auth_digest requires APR with random and shared memory support
+#endif
+
 /* struct to hold the configuration info */
 
 typedef struct digest_config_struct {
-    const char  *dir_name;
     authn_provider_list *providers;
-    const char  *realm;
-    apr_array_header_t *qop_list;
-    apr_sha1_ctx_t  nonce_ctx;
     apr_time_t    nonce_lifetime;
     int          check_nc;
-    const char  *algorithm;
+    const char  *algorithm; /* currently a constant (MD5). */
     char        *uri_list;
 } digest_config_rec;
 
@@ -118,11 +121,20 @@ typedef struct digest_config_struct {
 
 /* client list definitions */
 
+/* Identifies a client entry. This is the value sent to the client in the
+ * opaque field of the challenge, and echoed back in its Authorization
+ * header; zero is never a valid id, and means "no client". Ids are counted
+ * out by client_id_counter, so this must remain the type which the atomics
+ * used on it take, and the "%u"/"%x" formats below must match it. */
+typedef apr_uint32_t client_id_t;
+
 typedef struct hash_entry {
-    unsigned long      key;                     /* the key for this entry    */
+    client_id_t        key;                     /* the key for this entry    */
     struct hash_entry *next;                    /* next entry in the bucket  */
-    unsigned long      nonce_count;             /* for nonce-count checking  */
-    char               last_nonce[NONCE_LEN+1]; /* for one-time nonce's      */
+    unsigned long      nonce_count;             /* highest nonce-count seen
+                                                 * for last_nonce_time       */
+    apr_time_t         last_nonce_time;         /* nonce of the last request
+                                                 * accepted for this client  */
 } client_entry;
 
 static struct hash_table {
@@ -139,6 +151,14 @@ static struct hash_table {
 
 enum hdr_sts { NO_HEADER, NOT_DIGEST, INVALID, VALID };
 
+/* Outcome of checking a request's nonce and nonce-count against the state
+ * tracked for its client. */
+enum nonce_state {
+    NONCE_ACCEPTED,     /* recorded as the latest used by this client */
+    NONCE_STALE,        /* already used, or the client is unknown */
+    NONCE_BAD_COUNT     /* nonce-count did not increase: possible replay */
+};
+
 typedef struct digest_header_struct {
     const char           *scheme;
     const char           *realm;
@@ -150,7 +170,7 @@ typedef struct digest_header_struct {
     const char           *algorithm;
     const char           *cnonce;
     const char           *opaque;
-    unsigned long         opaque_num;
+    client_id_t           opaque_num;
     const char           *message_qop;
     const char           *nonce_count;
     /* the following fields are not (directly) from the header */
@@ -160,7 +180,6 @@ typedef struct digest_header_struct {
     enum hdr_sts          auth_hdr_sts;
     int                   needed_auth;
     const char           *ha1;
-    client_entry         *client;
 } digest_header_rec;
 
 
@@ -177,12 +196,10 @@ static unsigned char *secret;
 
 static apr_shm_t      *client_shm =  NULL;
 static apr_rmm_t      *client_rmm = NULL;
-static unsigned long  *op
~~~

Relevant Focal source excerpts:

~~~c

Focal lines 10..41
10  * Unless required by applicable law or agreed to in writing, software
11  * distributed under the License is distributed on an "AS IS" BASIS,
12  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
13  * See the License for the specific language governing permissions and
14  * limitations under the License.
15  */
16 
17 /*
18  * mod_auth_digest: MD5 digest authentication
19  *
20  * Originally by Alexei Kosut <akosut@nueva.pvt.k12.ca.us>
21  * Updated to RFC-2617 by Ronald Tschal�r <ronald@innovation.ch>
22  * based on mod_auth, by Rob McCool and Robert S. Thau
23  *
24  * This module an updated version of modules/standard/mod_digest.c
25  * It is still fairly new and problems may turn up - submit problem
26  * reports to the Apache bug-database, or send them directly to me
27  * at ronald@innovation.ch.
28  *
29  * Open Issues:
30  *   - qop=auth-int (when streams and trailer support available)
31  *   - nonce-format configurability
32  *   - Proxy-Authorization-Info header is set by this module, but is
33  *     currently ignored by mod_proxy (needs patch to mod_proxy)
34  *   - The source of the secret should be run-time directive (with server
35  *     scope: RSRC_CONF)
36  *   - shared-mem not completely tested yet. Seems to work ok for me,
37  *     but... (definitely won't work on Windoze)
38  *   - Sharing a realm among multiple servers has following problems:
39  *     o Server name and port can't be included in nonce-hash
40  *       (we need two nonce formats, which must be configured explicitly)
41  *     o Nonce-count check can't be for equal, or then nonce-count checking

Focal lines 21..52
21  * Updated to RFC-2617 by Ronald Tschal�r <ronald@innovation.ch>
22  * based on mod_auth, by Rob McCool and Robert S. Thau
23  *
24  * This module an updated version of modules/standard/mod_digest.c
25  * It is still fairly new and problems may turn up - submit problem
26  * reports to the Apache bug-database, or send them directly to me
27  * at ronald@innovation.ch.
28  *
29  * Open Issues:
30  *   - qop=auth-int (when streams and trailer support available)
31  *   - nonce-format configurability
32  *   - Proxy-Authorization-Info header is set by this module, but is
33  *     currently ignored by mod_proxy (needs patch to mod_proxy)
34  *   - The source of the secret should be run-time directive (with server
35  *     scope: RSRC_CONF)
36  *   - shared-mem not completely tested yet. Seems to work ok for me,
37  *     but... (definitely won't work on Windoze)
38  *   - Sharing a realm among multiple servers has following problems:
39  *     o Server name and port can't be included in nonce-hash
40  *       (we need two nonce formats, which must be configured explicitly)
41  *     o Nonce-count check can't be for equal, or then nonce-count checking
42  *       must be disabled. What we could do is the following:
43  *       (expected < received) ? set expected = received : issue error
44  *       The only problem is that it allows replay attacks when somebody
45  *       captures a packet sent to one server and sends it to another
46  *       one. Should we add "AuthDigestNcCheck Strict"?
47  *   - expired nonces give amaya fits.
48  *   - MD5-sess and auth-int are not yet implemented. An incomplete
49  *     implementation has been removed and can be retrieved from svn history.
50  */
51 
52 #include "apr_sha1.h"

Focal lines 48..79
48  *   - MD5-sess and auth-int are not yet implemented. An incomplete
49  *     implementation has been removed and can be retrieved from svn history.
50  */
51 
52 #include "apr_sha1.h"
53 #include "apr_base64.h"
54 #include "apr_lib.h"
55 #include "apr_time.h"
56 #include "apr_errno.h"
57 #include "apr_global_mutex.h"
58 #include "apr_strings.h"
59 
60 #define APR_WANT_STRFUNC
61 #include "apr_want.h"
62 
63 #include "ap_config.h"
64 #include "httpd.h"
65 #include "http_config.h"
66 #include "http_core.h"
67 #include "http_request.h"
68 #include "http_log.h"
69 #include "http_protocol.h"
70 #include "apr_uri.h"
71 #include "util_md5.h"
72 #include "util_mutex.h"
73 #include "apr_shm.h"
74 #include "apr_rmm.h"
75 #include "ap_provider.h"
76 
77 #include "mod_auth.h"
78 
79 #if APR_HAVE_UNISTD_H
~~~

## CVE-2026-106023.patch

Previous result: skipped

Touched paths: modules/md/md_core.c, modules/md/mod_md.c, modules/md/mod_md_status.c

### Dry run fuzz=0 exit=1

~~~text
checking file modules/md/md_core.c
Hunk #1 succeeded at 190 (offset 25 lines).
checking file modules/md/mod_md.c
Hunk #1 FAILED at 1412.
1 out of 1 hunk FAILED
checking file modules/md/mod_md_status.c
Hunk #1 succeeded at 72 (offset -5 lines).

~~~

### Dry run fuzz=1 exit=1

~~~text
checking file modules/md/md_core.c
Hunk #1 succeeded at 190 (offset 25 lines).
checking file modules/md/mod_md.c
Hunk #1 FAILED at 1412.
1 out of 1 hunk FAILED
checking file modules/md/mod_md_status.c
Hunk #1 succeeded at 72 (offset -5 lines).

~~~

### Dry run fuzz=2 exit=1

~~~text
checking file modules/md/md_core.c
Hunk #1 succeeded at 190 (offset 25 lines).
checking file modules/md/mod_md.c
Hunk #1 FAILED at 1412.
1 out of 1 hunk FAILED
checking file modules/md/mod_md_status.c
Hunk #1 succeeded at 72 (offset -5 lines).

~~~

### modules/md/md_core.c

~~~diff
--- a/modules/md/md_core.c
+++ b/modules/md/md_core.c
@@ -165,6 +165,9 @@ md_t *md_get_by_name(struct apr_array_he
 md_t *md_get_by_domain(struct apr_array_header_t *mds, const char *domain)
 {
     int i;
+    if (!domain) {
+        return NULL;
+    }
     for (i = 0; i < mds->nelts; ++i) {
         md_t *md = APR_ARRAY_IDX(mds, i, md_t *);
         if (md_contains(md, domain, 0)) {

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 157..188
157             if (md_contains_domains(m, md)) {
158                 return m;
159             }
160         }
161         /* no matching name and no md in the list has all domains.
162          * We consider that managed domain as closest match that contains at least one
163          * domain name from md, ONLY if there is no other one that also has.
164          */
165         cand_n = 0;
166         for (i = 0; i < mds->nelts; ++i) {
167             m = APR_ARRAY_IDX(mds, i, md_t *);
168             n = md_common_name_count(md, m);
169             if (n > cand_n) {
170                 candidate = m;
171                 cand_n = n;
172             }
173         }
174     }
175     return candidate;
176 }
177 
178 md_t *md_get_by_name(struct apr_array_header_t *mds, const char *name)
179 {
180     int i;
181     for (i = 0; i < mds->nelts; ++i) {
182         md_t *md = APR_ARRAY_IDX(mds, i, md_t *);
183         if (!strcmp(name, md->name)) {
184             return md;
185         }
186     }
187     return NULL;
188 }
~~~

### modules/md/mod_md.c

~~~diff
--- a/modules/md/mod_md.c
+++ b/modules/md/mod_md.c
@@ -1412,6 +1412,11 @@ static int md_http_challenge_pr(request_
         && !strncmp(ACME_CHALLENGE_PREFIX, r->parsed_uri.path, sizeof(ACME_CHALLENGE_PREFIX)-1)) {
         sc = ap_get_module_config(r->server->module_config, &md_module);
         if (sc && sc->mc) {
+            if (!r->hostname) {
+                /* No Host: (e.g. an HTTP/1.0 request without one) means no
+                 * domain to look up; leave the request to normal handling. */
+                return DECLINED;
+            }
             ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                           "access inside /.well-known/acme-challenge for %s%s",
                           r->hostname, r->parsed_uri.path);

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 1285..1284

~~~

### modules/md/mod_md_status.c

~~~diff
--- a/modules/md/mod_md_status.c
+++ b/modules/md/mod_md_status.c
@@ -77,6 +77,7 @@ int md_http_cert_status(request_rec *r)
     /* We are looking for information about a staged certificate */
     sc = ap_get_module_config(r->server->module_config, &md_module);
     if (!sc || !sc->mc || !sc->mc->reg || !sc->mc->certificate_status_enabled) return DECLINED;
+    if (!r->hostname) return DECLINED;
     md = md_get_by_domain(sc->mc->mds, r->hostname);
     if (!md) return DECLINED;
 

~~~

Relevant Focal source excerpts:

~~~c

Focal lines 69..100
69     ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
70                   "requesting status for: %s", r->hostname);
71     
72     /* We are looking for information about a staged certificate */
73     sc = ap_get_module_config(r->server->module_config, &md_module);
74     if (!sc || !sc->mc || !sc->mc->reg || !sc->mc->certificate_status_enabled) return DECLINED;
75     md = md_get_by_domain(sc->mc->mds, r->hostname);
76     if (!md) return DECLINED;
77 
78     if (r->method_number != M_GET) {
79         ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
80                       "md(%s): status supports only GET", md->name);
81         return HTTP_NOT_IMPLEMENTED;
82     }
83     
84     ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
85                   "requesting status for MD: %s", md->name);
86 
87     if (APR_SUCCESS != (rv = md_status_get_md_json(&mdj, md, sc->mc->reg, r->pool))) {
88         ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10175)
89                       "loading md status for %s", md->name);
90         return HTTP_INTERNAL_SERVER_ERROR;
91     }
92     
93     ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
94                   "status for MD: %s is %s", md->name, md_json_writep(mdj, r->pool, MD_JSON_FMT_INDENT));
95 
96     resp = md_json_create(r->pool);
97     
98     if (md_json_has_key(mdj, MD_KEY_CERT, MD_KEY_VALID_UNTIL, NULL)) {
99         md_json_sets(md_json_gets(mdj, MD_KEY_CERT, MD_KEY_VALID_UNTIL, NULL), 
100                      resp, MD_KEY_VALID_UNTIL, NULL);
~~~

