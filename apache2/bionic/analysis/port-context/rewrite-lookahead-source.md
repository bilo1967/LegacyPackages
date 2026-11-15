# Bionic rewrite lookahead subrequest lifetime review

Positions containing ap_destroy_sub_req(rr): [1893, 1928]

## Bionic lines 1869-1907

```c
1869:             if (!result) {
1870:                 result = getenv(var);
1871:             }
1872:         }
1873:         else if (var[4] && !strncasecmp(var, "SSL", 3) && rewrite_ssl_lookup) {
1874:             result = rewrite_ssl_lookup(r->pool, r->server, r->connection, r,
1875:                                         var + 4);
1876:         }
1877:     }
1878:     else if (var[4] == ':') {
1879:         if (var[5]) {
1880:             request_rec *rr;
1881:             const char *path;
1882: 
1883:             if (!strncasecmp(var, "HTTP", 4)) {
1884:                 result = lookup_header(var+5, ctx);
1885:             }
1886:             else if (!strncasecmp(var, "LA-U", 4)) {
1887:                 if (ctx->uri && subreq_ok(r)) {
1888:                     path = ctx->perdir ? la_u(ctx) : ctx->uri;
1889:                     rr = ap_sub_req_lookup_uri(path, r, NULL);
1890:                     ctx->r = rr;
1891:                     result = apr_pstrdup(r->pool, lookup_variable(var+5, ctx));
1892:                     ctx->r = r;
1893:                     ap_destroy_sub_req(rr);
1894: 
1895:                     rewritelog((r, 5, ctx->perdir, "lookahead: path=%s var=%s "
1896:                                 "-> val=%s", path, var+5, result));
1897: 
1898:                     return (char *)result;
1899:                 }
1900:             }
1901:             else if (!strncasecmp(var, "LA-F", 4)) {
1902:                 if (ctx->uri && subreq_ok(r)) {
1903:                     path = ctx->uri;
1904:                     if (ctx->perdir && *path == '/') {
1905:                         /* sigh, the user wants a file based subrequest, but
1906:                          * we can't do one, since we don't know what the file
1907:                          * path is! In this case behave like LA-U.
```

## Bionic lines 1904-1942

```c
1904:                     if (ctx->perdir && *path == '/') {
1905:                         /* sigh, the user wants a file based subrequest, but
1906:                          * we can't do one, since we don't know what the file
1907:                          * path is! In this case behave like LA-U.
1908:                          */
1909:                         rr = ap_sub_req_lookup_uri(path, r, NULL);
1910:                     }
1911:                     else {
1912:                         if (ctx->perdir) {
1913:                             rewrite_perdir_conf *conf;
1914: 
1915:                             conf = ap_get_module_config(r->per_dir_config,
1916:                                                         &rewrite_module);
1917: 
1918:                             path = apr_pstrcat(r->pool, conf->directory, path,
1919:                                                NULL);
1920:                         }
1921: 
1922:                         rr = ap_sub_req_lookup_file(path, r, NULL);
1923:                     }
1924: 
1925:                     ctx->r = rr;
1926:                     result = apr_pstrdup(r->pool, lookup_variable(var+5, ctx));
1927:                     ctx->r = r;
1928:                     ap_destroy_sub_req(rr);
1929: 
1930:                     rewritelog((r, 5, ctx->perdir, "lookahead: path=%s var=%s "
1931:                                 "-> val=%s", path, var+5, result));
1932: 
1933:                     return (char *)result;
1934:                 }
1935:             }
1936:         }
1937:     }
1938: 
1939:     /* well, do it the hard way */
1940:     else {
1941:         apr_time_exp_t tm;
1942: 
```

