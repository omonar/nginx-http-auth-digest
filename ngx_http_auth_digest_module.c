
/*
 * Nginx http digest authentication module
 *
 * Based on ngx_http_auth_basic_module.c and ngx_limit_conn_module.c
 * written for Nginx project by Igor Sysoev.
 *
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)

#define ngx_auth_digest_str2_casecmp(m, c0, c1)                                                   \
    ((((uint32_t *) m)[0] & 0xffff) | 0x2020) == ((c1 << 8) | c0)

#define ngx_auth_digest_str3_casecmp(m, c0, c1, c2)                                               \
    ((((uint32_t *) m)[0] & 0xffffff) | 0x202020) == ((c2 << 16) | (c1 << 8) | c0)

#define ngx_auth_digest_str5_casecmp(m, c0, c1, c2, c3, c4)                                       \
    (((uint32_t *) m)[0] | 0x20202020) == ((c3 << 24) |(c2 << 16) | (c1 << 8) | c0)               \
        && (m[4] | 0x20) == c4

#define ngx_auth_digest_str6_casecmp(m, c0, c1, c2, c3, c4, c5)                                   \
    (((uint32_t *) m)[0] | 0x20202020) == ((c3 << 24) |(c2 << 16) | (c1 << 8) | c0)               \
        && ((((uint32_t *) m)[1] & 0xffff) | 0x2020) == ((c5 << 8) | c4)

#define ngx_auth_digest_str8_casecmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                           \
    (((uint32_t *) m)[0] | 0x20202020) == ((c3 << 24) |(c2 << 16) | (c1 << 8) | c0)               \
        && (((uint32_t *) m)[1] | 0x20202020) == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define ngx_auth_digest_str9_casecmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                       \
    (((uint32_t *) m)[0] | 0x20202020) == ((c3 << 24) |(c2 << 16) | (c1 << 8) | c0)               \
        && (((uint32_t *) m)[1] | 0x20202020) == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)       \
        && (m[8] | 0x20) == c8

#else

#define ngx_auth_digest_str2_casecmp(m, c0, c1)                                                   \
    ((m[1] << 8) | m[0] | 0x2020) == ((c1 << 8) | c0)

#define ngx_auth_digest_str3_casecmp(m, c0, c1, c2)                                               \
    ((m[2] << 16) | (m[1] << 8) | m[0] | 0x202020) == ((c2 << 16) | (c1 << 8) | c0)

#define ngx_auth_digest_str5_casecmp(m, c0, c1, c2, c3, c4)                                       \
    ((m[3] << 24) | (m[2] << 16) | (m[1] << 8) | m[0] | 0x20202020)                               \
        == ((c3 << 24) |(c2 << 16) | (c1 << 8) | c0)                                              \
        && (m[4] | 0x20) == c4

#define ngx_auth_digest_str6_casecmp(m, c0, c1, c2, c3, c4, c5)                                   \
    ((m[3] << 24) | (m[2] << 16) | (m[1] << 8) | m[0] | 0x20202020)                               \
        == ((c3 << 24) |(c2 << 16) | (c1 << 8) | c0)                                              \
        && ((m[4] << 8) | m[5] | 0x2020) == ((c4 << 8) | c5)

#define ngx_auth_digest_str8_casecmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                           \
    ((m[3] << 24) | (m[2] << 16) | (m[1] << 8) | m[0] | 0x20202020)                               \
        == ((c3 << 24) |(c2 << 16) | (c1 << 8) | c0)                                              \
        && ((m[7] << 24) | (m[6] << 16) | (m[5] << 8) | m[4] | 0x20202020)                        \
        == ((c7 << 24) |(c6 << 16) | (c5 << 8) | c4)                                              \

#define ngx_auth_digest_str9_casecmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                       \
    ((m[3] << 24) | (m[2] << 16) | (m[1] << 8) | m[0] | 0x20202020)                               \
        == ((c3 << 24) |(c2 << 16) | (c1 << 8) | c0)                                              \
        && ((m[7] << 24) | (m[6] << 16) | (m[5] << 8) | m[4] | 0x20202020)                        \
        == ((c7 << 24) |(c6 << 16) | (c5 << 8) | c4)                                              \
        && (m[8] | 0x20) == c8

#endif

#define NGX_HTTP_AUTH_DGST_MD5        1
#define NGX_HTTP_AUTH_DGST_MD5SESS    2

#define NGX_HTTP_AUTH_DGST_MD5_SIZE   16
#define NGX_HTTP_AUTH_DGST_BUF_SIZE   2048

/* Default parameters */
#define NGX_HTTP_AUTH_DGST_REPLAYS    512
#define NGX_HTTP_AUTH_DGST_EXPIRES    300

#define NGX_HTTP_AUTH_DGST_KEY_SIZE   NGX_HTTP_AUTH_DGST_MD5_SIZE
#define NGX_HTTP_AUTH_DGST_MAC_SIZE   NGX_HTTP_AUTH_DGST_MD5_SIZE

/* Anti-replay window */
#define NGX_HTTP_AUTH_DGST_ARBV_ELT   8
#define NGX_HTTP_AUTH_DGST_ARBV_LEN   64
#define NGX_HTTP_AUTH_DGST_ARBV_SIZE  ((NGX_HTTP_AUTH_DGST_ARBV_LEN                              \
                                          / NGX_HTTP_AUTH_DGST_ARBV_ELT) + 1)


typedef struct {
    u_char                         color;
    u_char                         len;
    u_short                        conn;
    uint32_t                       last;
    u_char                         arbv[NGX_HTTP_AUTH_DGST_ARBV_SIZE];
    u_char                         data[1];
} ngx_http_auth_digest_node_t;


typedef struct {
    ngx_shm_zone_t                *shm_zone;
    ngx_rbtree_node_t             *node;
} ngx_http_auth_digest_cleanup_t;


typedef struct {
    ngx_rbtree_t                  *rbtree;
} ngx_http_auth_digest_ctx_t;


typedef struct {
    ngx_str_t                      username;
    ngx_str_t                      realm;
    ngx_str_t                      nonce;
    ngx_str_t                      uri;
    ngx_str_t                      qop;
    ngx_str_t                      cnonce;
    ngx_str_t                      nc;
    ngx_str_t                      response;
    ngx_str_t                      opaque;
    ngx_str_t                      algorithm;
    ngx_str_t                      passwd;
    ngx_str_t                      method_name;
    ngx_uint_t                     ncbinary;
} ngx_http_auth_digest_auth_t;


typedef struct {
    time_t                         expires;
    ngx_uint_t                     unique;
    u_char                         hmac[NGX_HTTP_AUTH_DGST_MAC_SIZE];
} ngx_http_auth_digest_nonce_t;


typedef struct {
    ngx_str_t                      name;
    ngx_uint_t                     offset;
} ngx_http_auth_digest_field_t;


typedef struct {
    ngx_http_auth_digest_field_t   username;
    ngx_http_auth_digest_field_t   realm;
    ngx_http_auth_digest_field_t   nonce;
    ngx_http_auth_digest_field_t   cnonce;
    ngx_http_auth_digest_field_t   response;
    ngx_http_auth_digest_field_t   opaque;
    ngx_http_auth_digest_field_t   algorithm;
    ngx_http_auth_digest_field_t   nc;
    ngx_http_auth_digest_field_t   qop;
    ngx_http_auth_digest_field_t   uri;
} ngx_http_auth_digest_fields_t;


typedef struct {
    ngx_shm_zone_t                *shm_zone;
    time_t                         expires;
    ngx_uint_t                     replays;
    ngx_uint_t                     algorithm;
    ngx_http_complex_value_t       realm;
    ngx_str_t                      secret_key;
    ngx_http_complex_value_t       user_file;
} ngx_http_auth_digest_conf_t;


static ngx_int_t ngx_http_auth_digest_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_digest_user(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_digest_credentials(ngx_http_request_t *r,
    ngx_http_auth_digest_conf_t *adcf, ngx_http_auth_digest_auth_t *auth);
static ngx_int_t ngx_http_auth_digest_parse_field(ngx_http_request_t *r,
    ngx_str_t *credentials, ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_auth_digest_parse_header(ngx_http_request_t *r,
    ngx_str_t *credentials, ngx_http_auth_digest_auth_t *auth);
static ngx_int_t ngx_http_auth_digest_crypt_handler(ngx_http_request_t *r,
    ngx_http_auth_digest_conf_t *adcf, ngx_http_auth_digest_auth_t *auth,
    ngx_str_t *realm);
static void ngx_http_auth_digest_crypt(ngx_http_auth_digest_conf_t *adcf,
    ngx_http_auth_digest_auth_t *auth, u_char *response, ngx_uint_t rspauth);
static ngx_int_t ngx_http_auth_digest_set_challenge(ngx_http_request_t *r,
    ngx_http_auth_digest_conf_t *adcf, ngx_str_t *realm, ngx_uint_t stale);
static ngx_int_t ngx_http_auth_digest_set_authinfo(ngx_http_request_t *r,
    ngx_http_auth_digest_conf_t *adcf, ngx_http_auth_digest_auth_t *auth,
    ngx_uint_t nextnonce);
static uintptr_t ngx_http_auth_digest_generate_nonce(ngx_http_request_t *r,
    u_char *dst, ngx_str_t *secret_key, time_t expires);
static ngx_int_t ngx_http_auth_digest_verify_nonce(ngx_http_request_t *r,
    ngx_http_auth_digest_conf_t *adcf, ngx_http_auth_digest_auth_t *auth,
    ngx_http_auth_digest_nonce_t *nonce);
static void ngx_http_auth_digest_calculate_hmac(u_char *hash,
    ngx_str_t *message, ngx_str_t *secret_key);
static uintptr_t ngx_http_auth_digest_escape_string(u_char *dst,
    u_char *src, size_t size);
static void ngx_http_auth_digest_close(ngx_file_t *file);

static ngx_int_t ngx_http_auth_digest_add_variables(ngx_conf_t *cf);
static void *ngx_http_auth_digest_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_digest_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_digest_init(ngx_conf_t *cf);
static char *ngx_http_auth_digest_user_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_digest_secret_key(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_auth_digest_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static char * ngx_http_auth_digest_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char * ngx_http_auth_digest(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void ngx_http_auth_digest_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_rbtree_node_t * ngx_http_auth_digest_lookup(ngx_rbtree_t *rbtree,
    ngx_str_t *key, uint32_t hash);
static void ngx_http_auth_digest_cleanup(void *data);
static ngx_inline void ngx_http_auth_digest_cleanup_all(ngx_pool_t *pool);
static ngx_inline ngx_uint_t ngx_http_auth_digest_bitvector_get(u_char *bv,
    ngx_uint_t bit);
static ngx_inline void ngx_http_auth_digest_bitvector_set(u_char *bv,
    ngx_uint_t bit);
static ngx_int_t ngx_http_auth_digest_user_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
#if (NGX_DEBUG)
static void ngx_http_auth_digest_arbv_status(ngx_http_request_t *r, u_char *arbv);
#endif

static ngx_http_auth_digest_fields_t ngx_http_auth_digest_fields = {

    { ngx_string("username"),
      offsetof(ngx_http_auth_digest_auth_t, username) },

    { ngx_string("realm"),
      offsetof(ngx_http_auth_digest_auth_t, realm) },

    { ngx_string("nonce"),
      offsetof(ngx_http_auth_digest_auth_t, nonce) },

    { ngx_string("cnonce"),
          offsetof(ngx_http_auth_digest_auth_t, cnonce) },

    { ngx_string("response"),
      offsetof(ngx_http_auth_digest_auth_t, response) },

    { ngx_string("opaque"),
      offsetof(ngx_http_auth_digest_auth_t, opaque) },

    { ngx_string("algorithm"),
      offsetof(ngx_http_auth_digest_auth_t, algorithm) },

    { ngx_string("nc"),
      offsetof(ngx_http_auth_digest_auth_t, nc) },

    { ngx_string("qop"),
      offsetof(ngx_http_auth_digest_auth_t, qop) },

    { ngx_string("uri"),
      offsetof(ngx_http_auth_digest_auth_t, uri) },
};


static ngx_str_t ngx_http_auth_digest_user_name =
    ngx_string("auth_digest_user");


static ngx_conf_enum_t ngx_http_auth_digest_algorithms[] = {
    { ngx_string("MD5"), NGX_HTTP_AUTH_DGST_MD5 },
    { ngx_string("MD5-sess"), NGX_HTTP_AUTH_DGST_MD5SESS },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_auth_digest_commands[] = {

    { ngx_string("auth_digest_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_digest_zone,
      0,
      0,
      NULL },

    { ngx_string("auth_digest_user_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_digest_user_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_digest_conf_t, user_file),
      NULL },

    { ngx_string("auth_digest_secret_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_digest_secret_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_digest_conf_t, secret_key),
      NULL },

    { ngx_string("auth_digest"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_CONF_TAKE1234,
      ngx_http_auth_digest,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_digest_algorithm"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_digest_conf_t, algorithm),
      &ngx_http_auth_digest_algorithms },


      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_digest_module_ctx = {
    ngx_http_auth_digest_add_variables,    /* preconfiguration */
    ngx_http_auth_digest_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_digest_create_loc_conf,  /* create location configuration */
    ngx_http_auth_digest_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_auth_digest_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_digest_module_ctx,      /* module context */
    ngx_http_auth_digest_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_auth_digest_handler(ngx_http_request_t *r)
{
    off_t                         offset;
    ssize_t                       n;
    ngx_fd_t                      fd;
    ngx_int_t                     rc;
    ngx_err_t                     err;
    ngx_str_t                     realm, user_file, s;
    ngx_uint_t                    i, level, login, left, passwd;
    ngx_file_t                    file;
    ngx_http_auth_digest_auth_t   auth;
    ngx_http_auth_digest_conf_t  *adcf;
    u_char                       *last, buf[NGX_HTTP_AUTH_DGST_BUF_SIZE];
    enum {
        sw_login,
        sw_passwd,
        sw_skip
    } state;

    if (r->main->internal) {
        return NGX_DECLINED;
    }

    r->main->internal = 1;

    adcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_digest_module);

    if (adcf->realm.value.data == NULL || adcf->user_file.value.data == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, &adcf->realm, &realm) != NGX_OK) {
        return NGX_ERROR;
    }

    if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    rc = ngx_http_auth_digest_user(r);

    if (rc == NGX_DECLINED) {

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "No credentials provided for digest authentication");

        return ngx_http_auth_digest_set_challenge(r, adcf, &realm, 0);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_auth_digest_credentials(r, adcf, &auth);

    if (rc == NGX_DECLINED) {

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "Client replied with wrong realm or algorithm");

        return ngx_http_auth_digest_set_challenge(r, adcf, &realm, 0);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rc == NGX_ABORT) {

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "Client submitted bad request");

        return NGX_HTTP_BAD_REQUEST;
    }

    /* For simplicity we combine username and realm to form a single login */
    s.len = r->headers_in.user.len + sizeof(":") - 1 + realm.len;

    s.data = ngx_pnalloc(r->pool, s.len + 1);
    if (s.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = ngx_cpystrn(s.data, r->headers_in.user.data, r->headers_in.user.len + 1);
    /* Add separator as in the file with digest data */
    *last++ = ':';

    last = ngx_cpystrn(last, realm.data, realm.len + 1);
    /* Terminate string with colon rather than '\0' */
    *last = ':';

    if (ngx_http_complex_value(r, &adcf->user_file, &user_file) != NGX_OK) {
        return NGX_ERROR;
    }

    fd = ngx_open_file(user_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err == NGX_ENOENT) {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;

        } else {
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(level, r->connection->log, err,
                      ngx_open_file_n " \"%s\" failed", user_file.data);

        return rc;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.fd = fd;
    file.name = user_file;
    file.log = r->connection->log;

    state = sw_login;
    passwd = 0;
    login = 0;
    left = 0;
    offset = 0;

    for ( ;; ) {
        i = left;

        n = ngx_read_file(&file, buf + left, NGX_HTTP_AUTH_DGST_BUF_SIZE - left,
                          offset);

        if (n == NGX_ERROR) {
            ngx_http_auth_digest_close(&file);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (n == 0) {
            break;
        }

        for (i = left; i < left + n; i++) {
            switch (state) {

            case sw_login:
                if (login == 0) {

                    if (buf[i] == '#' || buf[i] == CR) {
                        state = sw_skip;
                        break;
                    }

                    if (buf[i] == LF) {
                        break;
                    }
                }

                /*
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "auth digest: i=%d buf[i]=%c login.data[i]=%c", login, buf[i], s.data[login]);
                */

                /* NB: Condition below checks for terminating colon sign */
                if (buf[i] != s.data[login]) {
                    state = sw_skip;
                    break;
                }

                if (login == s.len) {
                    state = sw_passwd;
                    passwd = i + 1;
                }

                login++;

                break;

            case sw_passwd:
                if (buf[i] == LF || buf[i] == CR || buf[i] == ':') {
                    buf[i] = '\0';

                    ngx_http_auth_digest_close(&file);

                    auth.passwd.len = i - passwd;
                    auth.passwd.data = &buf[passwd];

                    return ngx_http_auth_digest_crypt_handler(r, adcf, &auth, &realm);
                }

                break;

            case sw_skip:
                if (buf[i] == LF) {
                    state = sw_login;
                    login = 0;
                }

                break;
            }

        }

        if (state == sw_passwd) {
            left = left + n - passwd;
            ngx_memmove(buf, &buf[passwd], left);
            passwd = 0;
        } else {
            left = 0;
        }

        offset += n;
    }

    ngx_http_auth_digest_close(&file);

    if (state == sw_passwd) {
        auth.passwd.len = i - passwd;
        auth.passwd.data = ngx_pnalloc(r->pool, auth.passwd.len + 1);
        if (auth.passwd.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_cpystrn(auth.passwd.data, &buf[passwd], auth.passwd.len + 1);

        return ngx_http_auth_digest_crypt_handler(r, adcf, &auth, &realm);
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "user \"%V\" was not found in \"%V\"",
                  &r->headers_in.user, &user_file);

    return ngx_http_auth_digest_set_challenge(r, adcf, &realm, 0);
}


static ngx_int_t
ngx_http_auth_digest_user(ngx_http_request_t *r)
{
    ngx_str_t                    credentials, username, s;
    ngx_int_t                    rc;
    ngx_uint_t                   i;

    if (r->headers_in.user.len == 0 && r->headers_in.user.data != NULL) {
        return NGX_DECLINED;
    }

    r->headers_in.user.data = (u_char *) "";

    if (r->headers_in.authorization == NULL) {
        return NGX_DECLINED;
    }

    credentials = r->headers_in.authorization->value;

    if (credentials.len < sizeof("Digest ") - 1
        || ngx_strncasecmp(credentials.data, (u_char *) "Digest ",
                           sizeof("Digest ") - 1)
           != 0)
    {
        return NGX_DECLINED;
    }

    credentials.len -= sizeof("Digest ") - 1;
    credentials.data += sizeof("Digest ") - 1;

    while (credentials.len && credentials.data[0] == ' ') {
        credentials.len--;
        credentials.data++;
    }

    if (credentials.len == 0) {
        return NGX_DECLINED;
    }

    rc = ngx_http_auth_digest_parse_field(r, &credentials,
            &ngx_http_auth_digest_fields.username.name, &username);

    if (rc != NGX_OK || username.len == 0) {
        return NGX_DECLINED;
    }

    /* Check username field */
    s.len = 0;
    s.data = ngx_pnalloc(r->pool, username.len + 1);
    if (s.data == NULL) {
        return NGX_ERROR;
    }

    /* Unescape a double quoted string */
    for (i = 0; i < username.len; i++) {
        if (username.data[i] == '\\' && i < username.len - 1) {
            i++;
        }
        s.data[s.len++] = username.data[i];
    }
    s.data[s.len] = '\0';

    r->headers_in.user.len = s.len;
    r->headers_in.user.data = s.data;

    r->headers_in.passwd.len = credentials.len;
    r->headers_in.passwd.data = credentials.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_digest_credentials(ngx_http_request_t *r,
    ngx_http_auth_digest_conf_t *adcf,
    ngx_http_auth_digest_auth_t *auth)
{
    u_char                       c, ch;
    ngx_str_t                   *credentials, server_realm;
    ngx_uint_t                   i, j, value;

    credentials = &r->headers_in.authorization->value;

    ngx_http_auth_digest_parse_header(r, credentials, auth);

    /* All required fields were received. We check them now. */
    if (auth->username.len == 0 || auth->realm.len == 0
        || auth->uri.len == 0 || auth->cnonce.len == 0
        || auth->nonce.len == 0
        /* Older Android versions use only 6 hexadecimal digits long counter */
        || (auth->nc.len != 8 && auth->nc.len != 6)
        || auth->response.len != 2*NGX_HTTP_AUTH_DGST_MD5_SIZE)
    {
        return NGX_ABORT;
    }

    /* Check realm */
    if (ngx_http_complex_value(r, &adcf->realm, &server_realm) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: rc=%d server realm=\"%V\"", 0, &server_realm);

    /* Check if client used server's realm */
    for (i = 0, j = 0; i < server_realm.len && j < auth->realm.len; i++, j++)
    {
        if (auth->realm.data[j] == '\\') {
            j++;
        }

        if (auth->realm.data[j] != server_realm.data[i]) {
            return NGX_DECLINED;
        }
    }

    if (j != auth->realm.len)
    {
        /* We have not reached the end of realm sent by client
         * or exceeded it which implies some possible realm
         * spoofing on client's side.
         */
        return NGX_DECLINED;
    }

    /* Check if nc is hexadecimal number */
    for (i = 0, value = 0; i < auth->nc.len; i++) {
        ch = auth->nc.data[i];

        if (ch >= '0' && ch <= '9') {
            value = value * 16 + (ch - '0');
            continue;
        }

        c = (u_char) (ch | 0x20);

        if (c >= 'a' && c<= 'f') {
            value = value * 16 + (c - 'a' + 10);
            continue;
        }

        return NGX_ABORT;
    }

    auth->ncbinary = value;

    /* Check if response is hexadecimal number */
    for (i = 0; i < 2*NGX_HTTP_AUTH_DGST_MD5_SIZE; i++) {
        ch = auth->response.data[i];

        if (ch >= '0' && ch <= '9') {
            continue;
        }

        c = (u_char) (ch | 0x20);

        if (c >= 'a' && c<= 'f') {
            continue;
        }

        return NGX_ABORT;
    }

    /* Check quality of protection field */
    if (auth->qop.len != sizeof("auth") - 1
        || ngx_strncmp(auth->qop.data, (u_char *) "auth",
                       sizeof("auth") - 1)
           != 0)
    {
        return NGX_ABORT;
    }

    /* Check algorithm field */
    if (auth->algorithm.len) {
        /* Check for valid algorithm */
        for (i = 0; ngx_http_auth_digest_algorithms[i].name.len != 0; i++) {
            if (auth->algorithm.len == ngx_http_auth_digest_algorithms[i].name.len
                && ngx_strncmp(auth->algorithm.data,
                               ngx_http_auth_digest_algorithms[i].name.data,
                               ngx_http_auth_digest_algorithms[i].name.len)
                == 0)
            {
                break;
            }
        }

        /* Unknown algorithm */
        if (ngx_http_auth_digest_algorithms[i].name.len == 0) {
            return NGX_ABORT;
        }

        /* Check if client used server's algorithm */
        if (auth->algorithm.len
            == ngx_http_auth_digest_algorithms[adcf->algorithm].name.len
            && ngx_strncmp(auth->algorithm.data,
                           ngx_http_auth_digest_algorithms[adcf->algorithm].name.data,
                           ngx_http_auth_digest_algorithms[adcf->algorithm].name.len)
            != 0)
        {
            return NGX_DECLINED;
        }
    }

    /* Request method */
    auth->method_name = r->method_name;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_digest_parse_field(ngx_http_request_t *r,
    ngx_str_t *credentials, ngx_str_t *name, ngx_str_t *value)
{
    u_char  *start, *last, *end, ch;

    ngx_str_null(value);

    if (name->len > credentials->len) {
        return NGX_DECLINED;
    }

    start = credentials->data;
    end = start + credentials->len;

    while (start < end) {

        if (ngx_strncasecmp(start, name->data, name->len) != 0) {
            goto skip;
        }

        for (start += name->len; start < end && *start == ' '; start++) {
            /* void */
        }

        if (start == end || *start++ != '=') {
            /* the invalid header value */
            goto skip;
        }

        while (start < end && *start == ' ') { start++; }

        for (last = start; last < end && *last != ','; last++) {
            /* void */
        }

        /* Double quoted string */
        if (*start == '\"' && start < last - 1 && *(last - 1) == '\"') {
            start++;
            last--;
        }

        value->len = last - start;
        value->data = start;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "auth digest: rc=%d %V=\"%V\"", NGX_OK, name, value);

        return NGX_OK;

    skip:

        while (start < end) {
            ch = *start++;
            if (ch == ',') {
                break;
            }
        }

        while (start < end && *start == ' ') { start++; }
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
       "auth digest: parse field: rc=%d %V=\"%V\"", NGX_DECLINED, name, value);

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_auth_digest_parse_header(ngx_http_request_t *r,
    ngx_str_t *credentials, ngx_http_auth_digest_auth_t *auth)
{
    u_char                        *start, *last, *end, ch;
    ngx_str_t                     *value;
    ngx_http_auth_digest_field_t  *field;

    ngx_memzero(auth, sizeof(ngx_http_auth_digest_auth_t));

    start = credentials->data;
    end = start + credentials->len;

    /* auth-scheme */
    while (start < end) {
        ch = *start++;
        if (ch == ' ') {
            break;
        }
    }

    /* white space */
    while (start < end && *start == ' ') { start++; }

    /* auth-param */
    while (start < end) {

        if (ngx_auth_digest_str2_casecmp(start, 'n', 'c'))
        {
            field = &ngx_http_auth_digest_fields.nc;

        } else if (ngx_auth_digest_str3_casecmp(start, 'q', 'o', 'p'))
        {
            field = &ngx_http_auth_digest_fields.qop;

        } else if (ngx_auth_digest_str3_casecmp(start, 'u', 'r', 'i'))
        {
            field = &ngx_http_auth_digest_fields.uri;

        } else if (ngx_auth_digest_str5_casecmp(start, 'n', 'o', 'n', 'c', 'e'))
        {
            field = &ngx_http_auth_digest_fields.nonce;

        } else if (ngx_auth_digest_str5_casecmp(start, 'r', 'e', 'a', 'l', 'm'))
        {
            field = &ngx_http_auth_digest_fields.realm;

        } else if (ngx_auth_digest_str6_casecmp(start, 'c', 'n', 'o', 'n', 'c', 'e'))
        {
            field = &ngx_http_auth_digest_fields.cnonce;

        } else if (ngx_auth_digest_str6_casecmp(start, 'o', 'p', 'a', 'q', 'u', 'e'))
        {
            field = &ngx_http_auth_digest_fields.opaque;

        } else if (ngx_auth_digest_str8_casecmp(start, 'u', 's', 'e', 'r', 'n', 'a', 'm', 'e'))
        {
            field = &ngx_http_auth_digest_fields.username;

        } else if (ngx_auth_digest_str8_casecmp(start, 'r', 'e', 's', 'p', 'o', 'n', 's', 'e'))
        {
            field = &ngx_http_auth_digest_fields.response;

        } else if (ngx_auth_digest_str9_casecmp(start, 'a', 'l', 'g', 'o', 'r', 'i', 't', 'h', 'm'))
        {
            field = &ngx_http_auth_digest_fields.algorithm;

        } else {
            goto skip;

        }

        for (start += field->name.len; start < end && *start == ' '; start++) {
            /* void */
        }

        if (start == end || *start++ != '=') {
            /* the invalid header field */
            goto skip;
        }

        while (start < end && *start == ' ') { start++; }

        for (last = start; last < end && *last != ','; last++) {
            /* void */
        }

        /* Double quoted string */
        if (*start == '\"' && start < last - 1 && *(last - 1) == '\"') {
            start++;
            last--;
        }

        value = (ngx_str_t *) ((char *) auth + field->offset);

        value->len = last - start;
        value->data = start;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "auth digest: parse field %V=\"%V\"", &field->name, value);

    skip:

        while (start < end) {
            ch = *start++;
            if (ch == ',') {
                break;
            }
        }

        while (start < end && *start == ' ') { start++; }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_digest_crypt_handler(ngx_http_request_t *r,
    ngx_http_auth_digest_conf_t *adcf, ngx_http_auth_digest_auth_t *auth,
    ngx_str_t *realm)
{
    size_t                           i, j, n;
    u_char                           digest[2*NGX_HTTP_AUTH_DGST_MD5_SIZE + 1];
    time_t                           now;
    uint32_t                         ch;
    ngx_int_t                        rc;
    ngx_str_t                        key;
    ngx_slab_pool_t                 *shpool;
    ngx_rbtree_node_t               *node, *root, *sentinel;
    ngx_pool_cleanup_t              *cln;
    ngx_http_auth_digest_ctx_t      *ctx;
    ngx_http_auth_digest_node_t     *lc;
    ngx_http_auth_digest_nonce_t     nonce;
    ngx_http_auth_digest_cleanup_t  *lccln;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: user: \"%V\" pwd: \"%s\"",
                   &r->headers_in.user, auth->passwd.data);

    ngx_http_auth_digest_crypt(adcf, auth, digest, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: Server-side hash: \"%s\"", digest);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: Client-side hash: \"%V\"", &auth->response);

    /* Best-effort constant-time comparison of strings in C */
    for (n = 0, ch = 0; n < 2*NGX_HTTP_AUTH_DGST_MD5_SIZE; n++) {
        ch |= auth->response.data[n] ^ digest[n];
    }

    if (ch != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "user \"%V\": password mismatch",
                      &r->headers_in.user);

        return ngx_http_auth_digest_set_challenge(r, adcf, realm, 0);
    }

    /* Client's response is correct */

    /* Verify that nonce has not been tampered */
    rc = ngx_http_auth_digest_verify_nonce(r, adcf, auth, &nonce);

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rc == NGX_ABORT) {
        /* Client probably attempted to tamper the nonce */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "Incorrect nonce received from client");

        return ngx_http_auth_digest_set_challenge(r, adcf, realm, 0);
    }

    /* Check timestamp */
    now = ngx_time();

    /*
     * Mark the oldest expired nonce for cleanup
     *
     * Marking all expired nonces is problematic because actual node deletion
     * and tree rebalancing is postponed to the end of request processing.
     *
     * To mark all nodes, one should somehow mark already processed nodes for
     * ngx_rbtree_min function.
     */

    ctx = adcf->shm_zone->data;

    root = ctx->rbtree->root;

    sentinel = ctx->rbtree->sentinel;

    if (root != sentinel) {

        node = ngx_rbtree_min(root, sentinel);

        if (node->key < (ngx_rbtree_key_t) now) {

            lc = (ngx_http_auth_digest_node_t *) &node->color;

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: Now is \"%08xT\" and nonce with ident \"%08xi:%08xi\" marked for cleanup",
                   now, node->key, *(ngx_uint_t *) lc->data);

            cln = ngx_pool_cleanup_add(r->pool,
                                       sizeof(ngx_http_auth_digest_cleanup_t));
            if (cln == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            cln->handler = ngx_http_auth_digest_cleanup;
            lccln = cln->data;

            lccln->shm_zone = adcf->shm_zone;
            lccln->node = node;
        }
    }

    /* nonce.expires = past + adcf->expires */
    if (nonce.expires < now) {
        /* Nonce expired */
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "auth digest: Now is \"%08xT\" and nonce with ident \"%08xT:%08xi\" expired",
                       now, nonce.expires, nonce.unique);

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "Expired credentials provided for digest authentication");

        /*Send new nonce with stale=true */
        return ngx_http_auth_digest_set_challenge(r, adcf, realm, 1);
    }

    /* Check if the nonce has already been seen */
    key.len  = offsetof(ngx_http_auth_digest_nonce_t, hmac)
             - offsetof(ngx_http_auth_digest_nonce_t, unique);

    key.data = (u_char *) &nonce.unique;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: Nonce with ident \"%08xT:%08xi\" client's counter value: %d",
                   nonce.expires, nonce.unique, auth->ncbinary);

    shpool = (ngx_slab_pool_t *) adcf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    node = ngx_http_auth_digest_lookup(ctx->rbtree, &key, nonce.expires);

    if (node == NULL) {

        n = offsetof(ngx_rbtree_node_t, color)
          + offsetof(ngx_http_auth_digest_node_t, data)
          + key.len;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "auth digest: Nonce with ident \"%08xT:%08xi\" of size %uz bytes stored in shared memory",
            nonce.expires, nonce.unique, n > shpool->min_size ? n : shpool->min_size);

#if 0
        /* Stress test */
        i = 0;
        do {
            node = ngx_slab_alloc_locked(shpool, n);

            i++;
        } while (node);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "auth digest: Maximum number of nonces that could be stored is %d",
                       i);
#endif

        node = ngx_slab_alloc_locked(shpool, n);

        if (node == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            ngx_http_auth_digest_cleanup_all(r->pool);
            return NGX_HTTP_SERVICE_UNAVAILABLE;
        }

        lc = (ngx_http_auth_digest_node_t *) &node->color;

        node->key = nonce.expires;
        lc->len = (u_char) key.len;
        lc->conn = 1;
        lc->last = auth->ncbinary;
        ngx_memzero(lc->arbv, NGX_HTTP_AUTH_DGST_ARBV_SIZE);
        ngx_memcpy(lc->data, key.data, key.len);

        ngx_rbtree_insert(ctx->rbtree, node);

    } else {

        lc = (ngx_http_auth_digest_node_t *) &node->color;

        if ((ngx_uint_t) lc->conn >= adcf->replays) {

            ngx_shmtx_unlock(&shpool->mutex);

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: Nonce with ident \"%08xT:%08xi\" reached maximum of %d uses",
                   nonce.expires, nonce.unique, adcf->replays);

            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "Expired credentials provided for digest authentication");

            /*Send new nonce with stale=true */
            return ngx_http_auth_digest_set_challenge(r, adcf, realm, 1);
        }

        lc->conn++;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: Nonce with ident \"%08xT:%08xi\" server's counter value: %d",
                   nonce.expires, nonce.unique, lc->last);
    /*
     * Requests may arrive out-of-order. Check sequence of seen nonce counters with
     * anti-replay window method as proposed in RFC6479
     */

#if (NGX_DEBUG)
    ngx_http_auth_digest_arbv_status(r, lc->arbv);
#endif

    /* Too old nonce counter value */
    if (auth->ncbinary + NGX_HTTP_AUTH_DGST_ARBV_LEN < lc->last)
    {
        /* Something could be wrong: Replay-attack? */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "Request too old and out of anti-replay window");

        return ngx_http_auth_digest_set_challenge(r, adcf, realm, 0);
    }

    /* New nonce counter value */
    if (auth->ncbinary > lc->last) {

        i = (lc->last - 1) / NGX_HTTP_AUTH_DGST_ARBV_ELT;

        n = (auth->ncbinary - 1) / NGX_HTTP_AUTH_DGST_ARBV_ELT;

        /*
         * Mark all nonce counters starting from the last one
         * up to the current one as not received
         */

        for (j = i + 1; j < n + 1; j++) {
            lc->arbv[j % NGX_HTTP_AUTH_DGST_ARBV_SIZE] = 0;
        }

        lc->last = auth->ncbinary;
    }

#if (NGX_DEBUG)
    ngx_http_auth_digest_arbv_status(r, lc->arbv);
#endif

    /* Nonce counter is within anti-replay window */
    if (ngx_http_auth_digest_bitvector_get(lc->arbv, auth->ncbinary - 1) != 0)
    {
        /* Already seen nonce counter. Replay-attack */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "Replayed request");

        return ngx_http_auth_digest_set_challenge(r, adcf, realm, 0);
    }

    ngx_http_auth_digest_bitvector_set(lc->arbv, auth->ncbinary - 1);

#if (NGX_DEBUG)
    ngx_http_auth_digest_arbv_status(r, lc->arbv);
#endif

    return ngx_http_auth_digest_set_authinfo(r, adcf, auth, 0);
}


static void
ngx_http_auth_digest_crypt(ngx_http_auth_digest_conf_t *adcf,
    ngx_http_auth_digest_auth_t *auth,
    u_char *digest, ngx_uint_t rspauth)
{
    ngx_md5_t   md5;
    u_char     *last, hash[NGX_HTTP_AUTH_DGST_MD5_SIZE];
    u_char      ha1[2*NGX_HTTP_AUTH_DGST_MD5_SIZE + 1];
    u_char      ha2[2*NGX_HTTP_AUTH_DGST_MD5_SIZE + 1];

    /* Calculate HA2 */
    ngx_md5_init(&md5);

    if (rspauth == 0) {
        ngx_md5_update(&md5, auth->method_name.data, auth->method_name.len);
    }

    ngx_md5_update(&md5, (u_char *) ":", 1);

    ngx_md5_update(&md5, auth->uri.data, auth->uri.len);
    ngx_md5_final(hash, &md5);

    last = ngx_hex_dump(ha2, hash, NGX_HTTP_AUTH_DGST_MD5_SIZE);
    *last = '\0';

    /* Calculate HA1 */
    ngx_memcpy(ha1, auth->passwd.data, 2*NGX_HTTP_AUTH_DGST_MD5_SIZE);

    if (adcf->algorithm == NGX_HTTP_AUTH_DGST_MD5SESS) {
        ngx_md5_init(&md5);

        ngx_md5_update(&md5, auth->passwd.data, 2*NGX_HTTP_AUTH_DGST_MD5_SIZE);
        ngx_md5_update(&md5, (u_char *) ":", 1);

        ngx_md5_update(&md5, auth->nonce.data, auth->nonce.len);
        ngx_md5_update(&md5, (u_char *) ":", 1);

        ngx_md5_update(&md5, auth->cnonce.data, auth->cnonce.len);

        ngx_md5_final(hash, &md5);

        last = ngx_hex_dump(ha1, hash, NGX_HTTP_AUTH_DGST_MD5_SIZE);
        *last = '\0';
    }

    /* Calculate digest */
    ngx_md5_init(&md5);

    ngx_md5_update(&md5, ha1, 2*NGX_HTTP_AUTH_DGST_MD5_SIZE);
    ngx_md5_update(&md5, (u_char *) ":", 1);

    ngx_md5_update(&md5, auth->nonce.data, auth->nonce.len);
    ngx_md5_update(&md5, (u_char *) ":", 1);

    ngx_md5_update(&md5, auth->nc.data, auth->nc.len);
    ngx_md5_update(&md5, (u_char *) ":", 1);

    ngx_md5_update(&md5, auth->cnonce.data, auth->cnonce.len);
    ngx_md5_update(&md5, (u_char *) ":", 1);

    ngx_md5_update(&md5, auth->qop.data, auth->qop.len);
    ngx_md5_update(&md5, (u_char *) ":", 1);

    ngx_md5_update(&md5, ha2, 2*NGX_HTTP_AUTH_DGST_MD5_SIZE);

    ngx_md5_final(hash, &md5);

    last = ngx_hex_dump(digest, hash, NGX_HTTP_AUTH_DGST_MD5_SIZE);
    *last = '\0';
}


static ngx_int_t
ngx_http_auth_digest_set_challenge(ngx_http_request_t *r, ngx_http_auth_digest_conf_t *adcf,
    ngx_str_t *realm, ngx_uint_t stale)
{
    size_t                         len;
    u_char                        *challenge, *last;
    ngx_str_t                      algorithm;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Digest realm=\"\", nonce=\"\", qop=\"auth\"") - 1;

    /* Nonce length */
    len += ngx_http_auth_digest_generate_nonce(NULL, NULL, NULL, 0);

    /* Escaped realm length */
    len += ngx_http_auth_digest_escape_string(NULL, realm->data, realm->len);

    algorithm = ngx_http_auth_digest_algorithms[adcf->algorithm].name;

    if (adcf->algorithm == NGX_HTTP_AUTH_DGST_MD5SESS) {
        len += sizeof(", algorithm=\"\"") - 1 + algorithm.len;
    }

    if (stale) {
        len += sizeof(", stale=true") - 1;
    }

    challenge = ngx_pnalloc(r->pool, len + 1);
    if (challenge == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = ngx_cpystrn(challenge, (u_char *) "Digest realm=\"", sizeof("Digest realm=\""));
    last = (u_char *) ngx_http_auth_digest_escape_string(last, realm->data, realm->len);
    *last++ = '\"';

    last = ngx_cpystrn(last, (u_char *) ", nonce=\"", sizeof(", nonce=\""));
    last = (u_char *) ngx_http_auth_digest_generate_nonce(r, last, &adcf->secret_key, adcf->expires);
    *last++ = '\"';

    last = ngx_cpystrn(last, (u_char *) ", qop=\"auth\"", sizeof(", qop=\"auth\""));

    if (adcf->algorithm == NGX_HTTP_AUTH_DGST_MD5SESS) {
        last = ngx_sprintf(last, ", algorithm=\"%V\"", &algorithm);
    }

    if (stale) {
        last = ngx_sprintf(last, "%s", stale ? ", stale=true" : "");
    }

    /* Terminate string */
    *last = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: %s", challenge);

    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = challenge;
    r->headers_out.www_authenticate->value.len = len;

    return NGX_HTTP_UNAUTHORIZED;
}


static ngx_int_t
ngx_http_auth_digest_set_authinfo(ngx_http_request_t *r, ngx_http_auth_digest_conf_t *adcf,
    ngx_http_auth_digest_auth_t *auth, ngx_uint_t nextnonce)
{
    size_t      len;
    u_char     *authinfo, *last;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("nextnonce=\"\", qop=auth, rspauth=\"\", cnonce=\"\", nc=") - 1
        + auth->nonce.len + auth->cnonce.len + auth->nc.len
        + 2 * NGX_HTTP_AUTH_DGST_MD5_SIZE;

    authinfo = ngx_pnalloc(r->pool, len + 1);
    if (authinfo == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = ngx_cpystrn(authinfo, (u_char *) "nextnonce=\"", sizeof("nextnonce=\""));

    if (nextnonce == 1) {
        last = (u_char *) ngx_http_auth_digest_generate_nonce(r, last, &adcf->secret_key, adcf->expires);
    } else {
        last = ngx_cpystrn(last, auth->nonce.data, auth->nonce.len + 1);
    }
    *last++ = '\"';

    last = ngx_cpystrn(last, (u_char *) ", qop=auth", sizeof(", qop=auth"));

    last = ngx_cpystrn(last, (u_char *) ", rspauth=\"", sizeof(", rspauth=\""));

    ngx_http_auth_digest_crypt(adcf, auth, last, 1);
    last += 2 * NGX_HTTP_AUTH_DGST_MD5_SIZE;
    *last++ = '\"';

    last = ngx_cpystrn(last, (u_char *) ", cnonce=\"", sizeof(", cnonce=\""));
    last = ngx_cpystrn(last, auth->cnonce.data, auth->cnonce.len + 1);
    *last++ = '\"';

    last = ngx_cpystrn(last, (u_char *) ", nc=", sizeof(", nc="));
    last = ngx_cpystrn(last, auth->nc.data, auth->nc.len + 1);

    /* Terminate string */
    *last = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: %s", authinfo);

    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "Authentication-Info");
    r->headers_out.www_authenticate->value.data = authinfo;
    r->headers_out.www_authenticate->value.len = len;

    return NGX_OK;
}


static uintptr_t
ngx_http_auth_digest_generate_nonce(ngx_http_request_t *r, u_char *dst,
    ngx_str_t *secret_key, time_t expires)
{
    ngx_str_t                     message, binary, base64;
    ngx_http_auth_digest_nonce_t  nonce;
#if (NGX_DEBUG)
    u_char                        key[2*NGX_HTTP_AUTH_DGST_KEY_SIZE + 1];
#endif

    binary.len = sizeof(ngx_http_auth_digest_nonce_t);
    binary.data = (u_char *) &nonce;

    base64.len = ngx_base64_encoded_length(binary.len);

    if (dst == NULL) {
        return (uintptr_t) base64.len;
    }

#if (NGX_DEBUG)
    ngx_hex_dump(key, secret_key->data, NGX_HTTP_AUTH_DGST_KEY_SIZE);

    key[2*NGX_HTTP_AUTH_DGST_KEY_SIZE] = '\0';
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "auth digest: Nonce secret: \"%s\"", key);

    nonce.unique  = ngx_random();

    /*
     * We set the expiration time as timestamp rather
     * than the current time. This makes deletion of
     * expired nonces simpler because one does not need
     * to access configuration parameter adcf->expires
     * in ngx_http_auth_digest_cleanup function.
     */

    nonce.expires  = ngx_time();
    nonce.expires += expires;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "auth digest: Nonce ident:  \"%08xT:%08xi\"",
         nonce.expires, nonce.unique);

    message.len = offsetof(ngx_http_auth_digest_nonce_t, hmac);
    message.data = (u_char *) &nonce;

    ngx_http_auth_digest_calculate_hmac(nonce.hmac, &message, secret_key);

    base64.data = dst;

    ngx_encode_base64(&base64, &binary);

    return (uintptr_t) (dst + base64.len);
}


static ngx_int_t
ngx_http_auth_digest_verify_nonce(ngx_http_request_t *r, ngx_http_auth_digest_conf_t *adcf,
    ngx_http_auth_digest_auth_t *auth, ngx_http_auth_digest_nonce_t *nonce)
{
    ngx_int_t                     n, rc;
    ngx_str_t                     message, base64, binary;
    u_char                        ch;
    ngx_http_auth_digest_nonce_t  value;
#if (NGX_DEBUG)
    u_char                        buf[2*sizeof(ngx_http_auth_digest_nonce_t)];
    u_char                        key[2*NGX_HTTP_AUTH_DGST_KEY_SIZE + 1];
#endif

    ngx_memset(nonce, 0, sizeof(ngx_http_auth_digest_nonce_t));

#if (NGX_DEBUG)
    ngx_hex_dump(key, adcf->secret_key.data, NGX_HTTP_AUTH_DGST_KEY_SIZE);

    key[2*NGX_HTTP_AUTH_DGST_KEY_SIZE] = '\0';
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "auth digest: Nonce secret: \"%s\"", key);

    base64.len = ngx_http_auth_digest_generate_nonce(NULL, NULL, NULL, 0);

    if (auth->nonce.len != base64.len) {
        return NGX_ABORT;
    }

    binary.data = (u_char *) nonce;

    rc = ngx_decode_base64(&binary, &auth->nonce);

    if (rc != NGX_OK) {
        return NGX_ABORT;
    }

    message.len = offsetof(ngx_http_auth_digest_nonce_t, hmac);
    message.data = (u_char *) &value;

    ngx_memcpy(&value, nonce, message.len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "auth digest: Nonce ident:  \"%08xT:%08xi\"",
            value.expires, value.unique);

    ngx_http_auth_digest_calculate_hmac(value.hmac, &message, &adcf->secret_key);

#if (NGX_DEBUG)
    binary.data = (u_char *) &value;

    base64.data = buf;

    ngx_encode_base64(&base64, &binary);
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: Server-side nonce: \"%V\"", &base64);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: Client-side nonce: \"%V\"", &auth->nonce);

    /* Best-effort constant-time comparison of strings in C */
    for (n = 0, ch = 0; n < NGX_HTTP_AUTH_DGST_MAC_SIZE; n++) {
        ch |= nonce->hmac[n] ^ value.hmac[n];
    }

    if (ch != 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "auth digest: user \"%V\": Tampered nonce sent by client",
                &r->headers_in.user);

        return NGX_ABORT;
    }

    return NGX_OK;
}


static void
ngx_http_auth_digest_calculate_hmac(u_char *hash, ngx_str_t *message,
    ngx_str_t *secret_key)
{
    ngx_md5_t   md5;
    ngx_int_t   i;
    ngx_str_t   key;
    u_char      k_opad[64], k_ipad[64];

    /*
     * We use HMAC-MD5 construction which according to RFC6151
     * is still acceptable.
     */

    if (secret_key->len > 64) {
        ngx_md5_init(&md5);
        ngx_md5_update(&md5, secret_key->data, secret_key->len);
        ngx_md5_final(hash, &md5);

        key.len = NGX_HTTP_AUTH_DGST_MD5_SIZE;
        key.data = hash;
    } else {
        key.len = secret_key->len;
        key.data = secret_key->data;
    }

    ngx_memset(k_ipad, 0, sizeof(k_ipad));
    ngx_memset(k_opad, 0, sizeof(k_opad));
    ngx_memcpy(k_ipad, key.data, key.len);
    ngx_memcpy(k_opad, key.data, key.len);

    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    /* Inner MD5 */
    ngx_md5_init(&md5);

    ngx_md5_update(&md5, k_ipad, sizeof(k_ipad));

    ngx_md5_update(&md5, message->data, message->len);

    ngx_md5_final(hash, &md5);

    /* Outer MD5 */
    ngx_md5_init(&md5);

    ngx_md5_update(&md5, k_opad, sizeof(k_ipad));
    ngx_md5_update(&md5, hash, NGX_HTTP_AUTH_DGST_MD5_SIZE);
    ngx_md5_final(hash, &md5);
}


static uintptr_t
ngx_http_auth_digest_escape_string(u_char *dst, u_char *src, size_t size)
{
    u_char    ch;
    size_t    len;

    if (dst == NULL) {
        len = size;

        while (size) {
            ch = *src++;

            if (ch == '\\' || ch == '"') {
                len++;
            }

            size--;
        }

        return (uintptr_t) len;
    }

    while (size) {
        ch = *src++;

        if (ch == '\\' || ch == '"') {
            *dst++ = '\\';
        }

        *dst++ = ch;

        size--;
    }

    return (uintptr_t) dst;
}


static void
ngx_http_auth_digest_close(ngx_file_t *file)
{
    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file->name.data);
    }
}


static ngx_int_t
ngx_http_auth_digest_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_auth_digest_user_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_auth_digest_user_variable;

    return NGX_OK;
}


static void *
ngx_http_auth_digest_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_digest_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_digest_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     * conf->shm_zone = NULL;
     * conf->replays = 0;
     * conf->expires = 0;
     * conf->algorithm = 0;
     * conf->realm = NULL;
     * conf->user_file = NULL;
     * conf->secret_key = {0, NULL};
     */

    conf->expires = NGX_CONF_UNSET;
    conf->replays = NGX_CONF_UNSET_UINT;
    conf->algorithm = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_auth_digest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_digest_conf_t  *prev = parent;
    ngx_http_auth_digest_conf_t  *conf = child;

    ngx_uint_t                    n;
    ngx_str_t                     value;

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    if (conf->realm.value.data == NULL) {
        conf->realm = prev->realm;
    }

    if (conf->user_file.value.data == NULL) {
        conf->user_file = prev->user_file;
    }

    if (conf->secret_key.data == NULL) {

        if (prev->secret_key.data == NULL) {

            /* Default value is random key */
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "Random secret key for nonce generation created");

            value.len = NGX_HTTP_AUTH_DGST_KEY_SIZE;

            value.data = ngx_pcalloc(cf->pool, value.len + 1);
            if (value.data == NULL) {
                return NGX_CONF_ERROR;
            }

            for (n = 0; n < NGX_HTTP_AUTH_DGST_KEY_SIZE; n++) {
                value.data[n] = (u_char) ngx_random();
            }

            conf->secret_key.len = value.len;
            conf->secret_key.data = value.data;

        } else {
            conf->secret_key = prev->secret_key;
        }
    }

    ngx_conf_merge_uint_value(conf->algorithm, prev->algorithm, NGX_HTTP_AUTH_DGST_MD5);

    ngx_conf_merge_uint_value(conf->replays, prev->replays, NGX_HTTP_AUTH_DGST_REPLAYS);
    ngx_conf_merge_sec_value(conf->expires, prev->expires, NGX_HTTP_AUTH_DGST_EXPIRES);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_digest_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_digest_handler;

    return NGX_OK;
}


static char *
ngx_http_auth_digest_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_digest_conf_t       *adcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (adcf->user_file.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &adcf->user_file;
    ccv.zero = 1;
    ccv.conf_prefix = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_digest_secret_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_digest_conf_t  *adcf = conf;

    ngx_md5_t                     md5;
    ngx_str_t                    *value, key;

    if (adcf->secret_key.data) {
        return "is duplicate";
    }

    key.len = NGX_HTTP_AUTH_DGST_KEY_SIZE;

    key.data = ngx_pcalloc(cf->pool, key.len + 1);
    if (key.data == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    /* Convert to 128-bit long binary form by calculating MD5 hash */
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, value[1].data, value[1].len);
    ngx_md5_final(key.data, &md5);

    adcf->secret_key.len = key.len;
    adcf->secret_key.data = key.data;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_digest_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_auth_digest_ctx_t  *octx = data;

    size_t                       len;
    ngx_slab_pool_t             *shpool;
    ngx_rbtree_node_t           *sentinel;
    ngx_http_auth_digest_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        ctx->rbtree = octx->rbtree;

        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->rbtree = shpool->data;

        return NGX_OK;
    }

    ctx->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    shpool->data = ctx->rbtree;

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->rbtree, sentinel,
                    ngx_http_auth_digest_rbtree_insert_value);

    len = sizeof(" in auth_digest_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in auth_digest_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static char *
ngx_http_auth_digest_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                      *p;
    ssize_t                      size;
    ngx_str_t                   *value, name, s;
    ngx_uint_t                   i;
    ngx_shm_zone_t              *shm_zone;
    ngx_http_auth_digest_ctx_t  *ctx;

    value = cf->args->elts;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_digest_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    size = 0;
    name.len = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_auth_digest_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_auth_digest_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_digest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_digest_conf_t  *adcf = conf;

    time_t                             expires;
    ngx_int_t                          replays;
    ngx_str_t                         *value, s;
    ngx_uint_t                         i;
    ngx_shm_zone_t                    *shm_zone;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &adcf->realm;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    shm_zone = NULL;
    replays = adcf->replays;
    expires = adcf->expires;

    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        return NGX_CONF_OK;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            shm_zone = ngx_shared_memory_add(cf, &s, 0,
                                             &ngx_http_auth_digest_module);
            if (shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "replays=", 8) == 0) {

            replays = ngx_atoi(value[i].data + 8, value[i].len - 8);
            if (replays <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid number of replays \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (replays > 65535) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "number of replays must be less than 65536");
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "expires=", 8) == 0) {

            expires = ngx_atotm(value[i].data + 8, value[i].len - 8);
            if (expires <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid expires time \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }


    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown auth_digest_zone \"%V\"",
                           &shm_zone->shm.name);
        return NGX_CONF_ERROR;
    }

    adcf->shm_zone = shm_zone;
    adcf->replays = replays;
    adcf->expires = expires;

    return NGX_CONF_OK;
}


static void
ngx_http_auth_digest_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t            **p;
    ngx_http_auth_digest_node_t   *adn, *adnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            adn = (ngx_http_auth_digest_node_t *) &node->color;
            adnt = (ngx_http_auth_digest_node_t *) &temp->color;

            p = (ngx_memn2cmp(adn->data, adnt->data, adn->len, adnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_rbtree_node_t *
ngx_http_auth_digest_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key, uint32_t hash)
{
    ngx_int_t                     rc;
    ngx_rbtree_node_t            *node, *sentinel;
    ngx_http_auth_digest_node_t  *adn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        adn = (ngx_http_auth_digest_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, adn->data, key->len, (size_t) adn->len);

        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
ngx_http_auth_digest_cleanup(void *data)
{
    ngx_http_auth_digest_cleanup_t *lccln = data;

    ngx_slab_pool_t              *shpool;
    ngx_rbtree_node_t            *node;
    ngx_http_auth_digest_ctx_t   *ctx;
#if (NGX_DEBUG)
    ngx_http_auth_digest_node_t  *lc;
#endif

    ctx = lccln->shm_zone->data;
    shpool = (ngx_slab_pool_t *) lccln->shm_zone->shm.addr;
    node = lccln->node;

#if (NGX_DEBUG)
    lc = (ngx_http_auth_digest_node_t *) &node->color;
#endif

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, lccln->shm_zone->shm.log, 0,
           "auth digest: Nonce (%08xd) with %d connections cleared",
            node->key, lc->conn);

    ngx_shmtx_lock(&shpool->mutex);

    ngx_rbtree_delete(ctx->rbtree, node);
    ngx_slab_free_locked(shpool, node);

    ngx_shmtx_unlock(&shpool->mutex);
}


static ngx_inline void
ngx_http_auth_digest_cleanup_all(ngx_pool_t *pool)
{
    ngx_pool_cleanup_t  *cln;

    cln = pool->cleanup;

    while (cln && cln->handler == ngx_http_auth_digest_cleanup) {
        ngx_http_auth_digest_cleanup(cln->data);
        cln = cln->next;
    }

    pool->cleanup = cln;
}


static ngx_inline ngx_uint_t
ngx_http_auth_digest_bitvector_get(u_char *bv, ngx_uint_t bit)
{
    ngx_uint_t  m, n;

    n = bit / NGX_HTTP_AUTH_DGST_ARBV_ELT;
    m = bit % NGX_HTTP_AUTH_DGST_ARBV_ELT;

    return bv[n % NGX_HTTP_AUTH_DGST_ARBV_SIZE] & (1 << m);
}


static ngx_inline void
ngx_http_auth_digest_bitvector_set(u_char *bv, ngx_uint_t bit)
{
    ngx_uint_t  m, n;

    n = bit / NGX_HTTP_AUTH_DGST_ARBV_ELT;
    m = bit % NGX_HTTP_AUTH_DGST_ARBV_ELT;

    bv[n % NGX_HTTP_AUTH_DGST_ARBV_SIZE] |= (1 << m);
}


static ngx_int_t
ngx_http_auth_digest_user_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_int_t  rc;

    rc = ngx_http_auth_digest_user(r);

    if (rc == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    v->len = r->headers_in.user.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->headers_in.user.data;

    return NGX_OK;
}


#if (NGX_DEBUG)
static void ngx_http_auth_digest_arbv_status(ngx_http_request_t *r, u_char *arbv)
{
    ngx_uint_t  i, j, n;
    u_char      s[NGX_HTTP_AUTH_DGST_ARBV_SIZE * NGX_HTTP_AUTH_DGST_ARBV_ELT + 1];

    for (i = 0; i < NGX_HTTP_AUTH_DGST_ARBV_SIZE * NGX_HTTP_AUTH_DGST_ARBV_ELT; i++)
    {
        j = i / NGX_HTTP_AUTH_DGST_ARBV_ELT;
        n = i % NGX_HTTP_AUTH_DGST_ARBV_ELT;

        s[i] = ((arbv[j] & (1 << n)) == 0) ? '0' : '1';
    }
    s[NGX_HTTP_AUTH_DGST_ARBV_SIZE * NGX_HTTP_AUTH_DGST_ARBV_ELT] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth digest: Anti-replay window %s", &s);
}
#endif
