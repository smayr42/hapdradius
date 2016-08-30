#include <sqlite3.h>
#include <syslog.h>
#include "hostapd.h"

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define HTON32(x) (x)
#else
#define HTON32(val)                                                 \
    ((uint32_t)((((uint32_t)(val) & (uint32_t)0x000000ffU) << 24) | \
                (((uint32_t)(val) & (uint32_t)0x0000ff00U) << 8) |  \
                (((uint32_t)(val) & (uint32_t)0x00ff0000U) >> 8) |  \
                (((uint32_t)(val) & (uint32_t)0xff000000U) >> 24)))
#endif

#define STRINGIFY(x) #x
const char *create_tables_sql =
#include "schema.sql"
    ;

#define ACCT_UPDATE_INTERVAL 300

static uint32_t interim_update_buf = HTON32(ACCT_UPDATE_INTERVAL);

static struct wpabuf interim_update_value = {
    .size = 4, .used = 4, .buf = (uint8_t *)&interim_update_buf, .flags = WPABUF_FLAG_EXT_DATA
};

static struct hostapd_radius_attr interim_update_attr = {
    .type = RADIUS_ATTR_ACCT_INTERIM_INTERVAL, .val = &interim_update_value, .next = NULL
};

struct sqlite_ctx {
    sqlite3 *db;
    sqlite3_stmt *select_user;
    sqlite3_stmt *insert_acct;
    sqlite3_stmt *insert_auth;
};

struct config {
    char *ca_cert_file;
    char *server_cert_file;
    char *private_key_file;
    char *db_file;
    struct radius_server_conf radius;
};

static void
hostapd_logger_cb(void *ctx, const uint8_t *addr, unsigned int module, int level, const char *txt,
                  size_t len)
{
    wpa_printf(level, "radius: %s\n", txt);
}

static void
sqlite_logger_cb(void *pArg, int iErrCode, const char *zMsg)
{
    wpa_printf(MSG_ERROR, "sqlite(%d): %s\n", iErrCode, zMsg);
}

static char *
prepend_prefix(const char *path)
{
    const char *prefix = getenv("PREFIX");

    if (!prefix)
        prefix = ".";

    size_t full_path_length = strlen(prefix) + strlen(path) + 2;
    char *full_path = calloc(full_path_length, sizeof(char));

    snprintf(full_path, full_path_length, "%s/%s", prefix, path);

    return full_path;
}

static void *
tls_global_init(struct config *cfg)
{
    struct tls_config tconf = { 0 };
    struct tls_connection_params tparams = { 0 };
    void *tls_ctx;

    tls_ctx = tls_init(&tconf);
    if (tls_ctx == NULL)
        return NULL;

    tparams.ca_cert = cfg->ca_cert_file;
    tparams.client_cert = cfg->server_cert_file;
    tparams.private_key = cfg->private_key_file;

    if (tls_global_set_params(tls_ctx, &tparams)) {
        wpa_printf(MSG_ERROR, "Failed to set TLS parameters");
        return NULL;
    }

    if (tls_global_set_verify(tls_ctx, 0)) {
        wpa_printf(MSG_ERROR, "Failed to verify tls context");
        return NULL;
    }

    return tls_ctx;
}

static void
sqlite_deinit(struct sqlite_ctx **ctx)
{
    if (!ctx || !*ctx)
        return;

    struct sqlite_ctx *c = *ctx;
    sqlite3_finalize(c->select_user);
    sqlite3_finalize(c->insert_acct);
    sqlite3_finalize(c->insert_auth);
    sqlite3_close(c->db);
    free(c);

    *ctx = NULL;
}

static struct sqlite_ctx *
sqlite_init(struct config *cfg)
{
    struct sqlite_ctx *ctx = calloc(1, sizeof(struct sqlite_ctx));
    sqlite3_config(SQLITE_CONFIG_LOG, sqlite_logger_cb, NULL);

    char *db_file = cfg->db_file;
    if (sqlite3_open(db_file, &ctx->db) != SQLITE_OK) {
        sqlite_deinit(&ctx);
        wpa_printf(MSG_ERROR, "Failed to open file '%s'", db_file);
        return NULL;
    }

    if (sqlite3_exec(ctx->db, create_tables_sql, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite_deinit(&ctx);
        wpa_printf(MSG_ERROR, "Failed to create tables");
        return NULL;
    }

    const char select_user_sql[] =
        "SELECT username, password FROM users "
        "WHERE username == :username "
        "AND (expiration IS NULL OR strftime('%s', expiration) >= strftime('%s', 'now'))";

    if (sqlite3_prepare_v2(ctx->db, select_user_sql, -1, &ctx->select_user, NULL) != SQLITE_OK) {
        sqlite_deinit(&ctx);
        wpa_printf(MSG_ERROR, "Failed to prepare statement");
        return NULL;
    }

    const char insert_acct_sql[] =
        "INSERT INTO accounting VALUES ("
        "CURRENT_TIMESTAMP,"
        ":session,"
        ":status,"
        ":username,"
        ":ap_mac,"
        ":client_mac,"
        ":session_time,"
        ":input_octets,"
        ":output_octets,"
        ":terminate_cause)";

    if (sqlite3_prepare_v2(ctx->db, insert_acct_sql, -1, &ctx->insert_acct, NULL) != SQLITE_OK) {
        sqlite_deinit(&ctx);
        wpa_printf(MSG_ERROR, "Failed to prepare statement");
        return NULL;
    }

    const char insert_auth_sql[] =
        "INSERT INTO requests VALUES ("
        "CURRENT_TIMESTAMP,"
        ":session,"
        ":status,"
        ":username,"
        ":ap_mac,"
        ":client_mac)";

    if (sqlite3_prepare_v2(ctx->db, insert_auth_sql, -1, &ctx->insert_auth, NULL) != SQLITE_OK) {
        sqlite_deinit(&ctx);
        wpa_printf(MSG_ERROR, "Failed to prepare statement");
        return NULL;
    }

    return ctx;
}

static int
get_eap_user(void *c, const uint8_t *identity, size_t identity_len, int phase2,
             struct eap_user *user)
{
    if (user == NULL)
        return 0;

    memset(user, 0, sizeof(*user));
    user->force_version = -1;

    if (!phase2) {
        user->methods[0].vendor = EAP_VENDOR_IETF;
        user->methods[0].method = EAP_TYPE_PEAP;
        return 0;
    }

    if (identity == NULL || identity_len <= 0 || identity_len > 1000) {
        wpa_printf(MSG_WARNING, "request for user with invalid identity for phase2");
        return -1;
    }

    int res = -1;
    struct sqlite_ctx *ctx = c;
    sqlite3_reset(ctx->select_user);
    int bind_res = sqlite3_bind_text(ctx->select_user, 1, (char *)identity, (int)identity_len,
                                     SQLITE_TRANSIENT);
    int step_res = sqlite3_step(ctx->select_user);

    if (bind_res == SQLITE_OK && step_res == SQLITE_ROW) {
        const unsigned char *password = sqlite3_column_text(ctx->select_user, 1);
        int password_len = sqlite3_column_bytes(ctx->select_user, 1);

        if (password && password_len > 0) {
            user->methods[0].vendor = EAP_VENDOR_IETF;
            user->methods[0].method = EAP_TYPE_MSCHAPV2;
            user->accept_attr = &interim_update_attr;
            user->password_len = (size_t)password_len;
            user->password = malloc(password_len);
            memcpy(user->password, password, password_len);
            res = 0;
        }
    }

    sqlite3_reset(ctx->select_user);
    sqlite3_clear_bindings(ctx->select_user);

    return res;
}

static void
bind_radius_int32_attr(sqlite3_stmt *stmt, const char *name, struct radius_msg *msg, uint8_t attr)
{
    int index = sqlite3_bind_parameter_index(stmt, name);
    if (index == 0) {
        wpa_printf(MSG_ERROR, "statement has no parameter '%s'", name);
        return;
    }

    uint32_t value;
    if (radius_msg_get_attr_int32(msg, attr, &value) != 0)
        sqlite3_bind_null(stmt, index);
    else
        sqlite3_bind_int(stmt, index, value);
}

static void
bind_radius_string_attr(sqlite3_stmt *stmt, const char *name, struct radius_msg *msg, uint8_t attr)
{
    int index = sqlite3_bind_parameter_index(stmt, name);
    if (index == 0) {
        wpa_printf(MSG_ERROR, "statement has no parameter '%s'", name);
        return;
    }

    uint8_t *str;
    size_t len;
    if (radius_msg_get_attr_ptr(msg, attr, &str, &len, NULL) != 0 || len == 0)
        sqlite3_bind_null(stmt, index);
    else
        sqlite3_bind_text(stmt, index, (char *)str, (int)len, SQLITE_TRANSIENT);
}

static void
acct_update(void *c, struct radius_msg *msg)
{
    struct sqlite_ctx *ctx = c;
    sqlite3_stmt *stmt = ctx->insert_acct;

    uint32_t type;
    if (radius_msg_get_attr_int32(msg, RADIUS_ATTR_ACCT_STATUS_TYPE, &type) != 0 ||
        (type != RADIUS_ACCT_STATUS_TYPE_START && type != RADIUS_ACCT_STATUS_TYPE_STOP &&
         type != RADIUS_ACCT_STATUS_TYPE_INTERIM_UPDATE)) {
        /* only log accounting start, stop and update messages */
        return;
    }

    sqlite3_reset(stmt);
    bind_radius_string_attr(stmt, ":session", msg, RADIUS_ATTR_ACCT_SESSION_ID);
    bind_radius_int32_attr(stmt, ":status", msg, RADIUS_ATTR_ACCT_STATUS_TYPE);
    bind_radius_string_attr(stmt, ":username", msg, RADIUS_ATTR_USER_NAME);
    bind_radius_string_attr(stmt, ":ap_mac", msg, RADIUS_ATTR_CALLED_STATION_ID);
    bind_radius_string_attr(stmt, ":client_mac", msg, RADIUS_ATTR_CALLING_STATION_ID);
    bind_radius_int32_attr(stmt, ":session_time", msg, RADIUS_ATTR_ACCT_SESSION_TIME);
    bind_radius_int32_attr(stmt, ":input_octets", msg, RADIUS_ATTR_ACCT_INPUT_OCTETS);
    bind_radius_int32_attr(stmt, ":output_octets", msg, RADIUS_ATTR_ACCT_OUTPUT_OCTETS);
    bind_radius_int32_attr(stmt, ":terminate_cause", msg, RADIUS_ATTR_ACCT_TERMINATE_CAUSE);

    if (sqlite3_step(stmt) != SQLITE_DONE)
        wpa_printf(MSG_ERROR, "inserting accounting data failed!");

    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
}

static void
auth_reply(void *c, struct radius_msg *request, struct radius_msg *reply)
{
    struct sqlite_ctx *ctx = c;
    sqlite3_stmt *stmt = ctx->insert_auth;

    if (!request || !reply) {
        wpa_printf(MSG_ERROR, "invalid request-reply pair (%p, %p)", request, reply);
        return;
    }

    uint8_t code = radius_msg_get_hdr(reply)->code;
    if (code != RADIUS_CODE_ACCESS_REJECT && code != RADIUS_CODE_ACCESS_ACCEPT)
        /* only log access accept/reject replies */
        return;

    sqlite3_reset(stmt);
    bind_radius_string_attr(stmt, ":session", request, RADIUS_ATTR_ACCT_SESSION_ID);
    sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":status"), code);
    bind_radius_string_attr(stmt, ":username", request, RADIUS_ATTR_USER_NAME);
    bind_radius_string_attr(stmt, ":ap_mac", request, RADIUS_ATTR_CALLED_STATION_ID);
    bind_radius_string_attr(stmt, ":client_mac", request, RADIUS_ATTR_CALLING_STATION_ID);

    if (sqlite3_step(stmt) != SQLITE_DONE)
        wpa_printf(MSG_ERROR, "inserting accounting data failed!");

    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
}

static void
config_deinit(struct config **cfg)
{
    if (!cfg || !*cfg)
        return;

    struct config *c = *cfg;
    free(c->ca_cert_file);
    free(c->server_cert_file);
    free(c->private_key_file);
    free(c->db_file);
    free(c->radius.client_file);
    free(c);

    *cfg = NULL;
}

static struct config *
config_init()
{
    struct config *cfg = calloc(1, sizeof(struct config));

    /* TODO: read from cmdline or config file */

    cfg->ca_cert_file = prepend_prefix("ca.crt");
    cfg->server_cert_file = prepend_prefix("server.crt");
    cfg->private_key_file = prepend_prefix("server.key");
    cfg->db_file = prepend_prefix("user.db");
    cfg->radius.client_file = prepend_prefix("radius.conf");

    cfg->radius.server_id = "radius";
    cfg->radius.auth_port = 1812;
    cfg->radius.acct_port = 1813;

    cfg->radius.get_eap_user = get_eap_user;
    cfg->radius.acct_update = acct_update;
    cfg->radius.auth_reply = auth_reply;

    return cfg;
}

static void
on_termination(int sig, void *signal_ctx)
{
    wpa_printf(MSG_DEBUG, "Terminating due to signal %d", sig);
    eloop_terminate();
}

int
main(int argc, char *argv[])
{
    struct config *cfg = config_init();

    if (getenv("SYSLOG") && atoi(getenv("SYSLOG")))
        wpa_debug_open_syslog();

    if (getenv("DEBUG") && atoi(getenv("DEBUG")))
        wpa_debug_level = MSG_MSGDUMP;
    else
        wpa_debug_level = MSG_INFO;

    if (os_program_init())
        return -1;

    hostapd_logger_register_cb(hostapd_logger_cb);

    if (eloop_init()) {
        wpa_printf(MSG_ERROR, "Failed to initialize event loop");
        return -1;
    }

    eloop_register_signal_terminate(on_termination, NULL);

    cfg->radius.conf_ctx = sqlite_init(cfg);
    if (!cfg->radius.conf_ctx) {
        wpa_printf(MSG_ERROR, "Failed to initialize sqlite");
        return -1;
    }

    cfg->radius.ssl_ctx = tls_global_init(cfg);
    if (!cfg->radius.ssl_ctx) {
        wpa_printf(MSG_ERROR, "Failed to initialize ssl context");
        return -1;
    }

    if (eap_server_register_methods()) {
        wpa_printf(MSG_ERROR, "Failed to register EAP methods");
        return -1;
    }

    struct radius_server_data *srv = radius_server_init(&cfg->radius);

    eloop_run();

    radius_server_deinit(srv);
    tls_deinit(cfg->radius.ssl_ctx);
    sqlite_deinit((struct sqlite_ctx **)&cfg->radius.conf_ctx);
    config_deinit(&cfg);

    eloop_destroy();
    eap_server_unregister_methods();
    os_program_deinit();

    return 0;
}
