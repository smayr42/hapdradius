/*
 * Example application using RADIUS client as a library
 * Copyright (c) 2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "eloop.h"
#include "crypto/tls.h"
#include "eap_server/eap.h"
#include "radius/radius_server.h"
#include "radius/radius.h"
#include "ap/ap_config.h"
#include <sqlite3.h>

#define DEBUG_LEVEL MSG_INFO //MSG_MSGDUMP
#define DEFAULT_PREFIX "."
#define CA_CERT "/ca.crt"
#define SERVER_CERT "/server.crt"
#define SERVER_KEY "/server.key"
#define CLIENT_FILE "/radius.conf"
#define DB_FILE "/user.db"
#define SERVER_ID "radius"
#define AUTH_PORT 1812
#define ACCT_PORT 1813
#define ACCT_UPDATE_INTERVAL 300

#define UNUSED(x) (void)(x)

/* DB SCHEMA

CREATE TABLE users
(
    firstname TEXT NOT NULL,
    lastname TEXT NOT NULL,
    username TEXT PRIMARY KEY NOT NULL,
    password TEXT NOT NULL,
    expiration TEXT DEFAULT NULL
);

CREATE TABLE accounting
(
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    session TEXT NOT NULL, --Acct-Session-Id (string)
    status INTEGER, --Acct-Status-Type (int32)
    username TEXT, --User-Name (string)
    ap_mac TEXT, --Called-Station-Id (string)
    client_mac TEXT, --Calling-Station-Id (string)
    session_time INTEGER, --Acct-Session-Time (int32)
    input_octets INTEGER, --Acct-Input-Octets (int32)
    output_octets INTEGER, --Acct-Output-Octets (int32)
    terminate_cause INTEGER --Acct-Terminate-Cause (int32)
);

TEST DATA

INSERT INTO users
    (firstname, lastname, username, password, expiration)
VALUES
    ('first1', 'last1', 'user1', 'pass1', date('now')),
    ('first2', 'last2', 'user2', 'pass2', NULL),
    ('first3', 'last3', 'user3', 'pass3', date('now','+9 months'));

 */

#define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))

static u32 interim_update_interval = SWAP_UINT32(ACCT_UPDATE_INTERVAL);

static struct wpabuf interim_update_value = {
		.size = 4,
		.used = 4,
		.buf = (u8*)&interim_update_interval,
		.flags = WPABUF_FLAG_EXT_DATA
};

static struct hostapd_radius_attr interim_update_attr = {
		.type = RADIUS_ATTR_ACCT_INTERIM_INTERVAL,
		.val = &interim_update_value,
		.next = NULL
};

struct sqlite_ctx {
	sqlite3 *db;
	sqlite3_stmt *select_user;
	sqlite3_stmt *insert_acct;
};

static void
hostapd_logger_cb(void *ctx, const u8 *addr, unsigned int module, int level, const char *txt, size_t len)
{
	UNUSED(ctx);
	UNUSED(addr);
	UNUSED(module);
	UNUSED(level);
	UNUSED(len);
	printf("RADIUS: %s\n", txt);
}

static void
sqlite_logger_cb(void *pArg, int iErrCode, const char *zMsg)
{
	UNUSED(pArg);
	printf("SQLITE: (%d) %s\n", iErrCode, zMsg);
}

char*
append_prefix(const char *path) {
	const char *prefix = getenv("PREFIX");

	if (!prefix)
		prefix = DEFAULT_PREFIX;

	char* full_path = calloc(strlen(prefix) + strlen(path) + 1, sizeof(char));
	strcat(full_path, prefix);
	strcat(full_path, path);
	return full_path;
}

static void*
init_tls()
{
	struct tls_config tconf;
	struct tls_connection_params tparams;
	void *tls_ctx;

	os_memset(&tconf, 0, sizeof(tconf));
	tls_ctx = tls_init(&tconf);
	if (tls_ctx == NULL)
		return NULL;

	os_memset(&tparams, 0, sizeof(tparams));
	tparams.ca_cert = append_prefix(CA_CERT);
	tparams.client_cert = append_prefix(SERVER_CERT);
	tparams.private_key = append_prefix(SERVER_KEY);

	if (tls_global_set_params(tls_ctx, &tparams)) {
		printf("Failed to set TLS parameters\n");
		return NULL;
	}

	if (tls_global_set_verify(tls_ctx, 0)) {
		printf("Failed to verify tls context\n");
		return NULL;
	}

	return tls_ctx;
}

static int
register_methods(void) {
	int ret = 0;

	ret = eap_server_identity_register();

	if (ret == 0)
		ret = eap_server_mschapv2_register();

	if (ret == 0)
		ret = eap_server_peap_register();

	return ret;

}

static void
sqlite_deinit(struct sqlite_ctx **ctx)
{
	if (!ctx || !*ctx)
		return;

	struct sqlite_ctx *c = *ctx;
	sqlite3_finalize(c->select_user);
	sqlite3_finalize(c->insert_acct);
	sqlite3_close(c->db);
	free(c);
	*ctx = NULL;
}

struct sqlite_ctx*
sqlite_init()
{
	struct sqlite_ctx *ctx = calloc(1, sizeof(struct sqlite_ctx));
	sqlite3_config(SQLITE_CONFIG_LOG, sqlite_logger_cb, NULL);

	char* db_file = append_prefix(DB_FILE);
	if (sqlite3_open(db_file, &ctx->db) != SQLITE_OK) {
		sqlite_deinit(&ctx);
		printf("Failed to open file '%s'\n", db_file);
		return NULL;
	}

	if (sqlite3_prepare_v2(ctx->db,

			"SELECT username, password FROM users "
					"WHERE username == :username AND (expiration IS NULL OR strftime('%s', expiration) >= strftime('%s', 'now'))",

			-1, &ctx->select_user, NULL) != SQLITE_OK) {

		sqlite_deinit(&ctx);
		printf("Failed to prepare statement\n");
		return NULL;
	}

	if (sqlite3_prepare_v2(ctx->db,

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
					":terminate_cause)",

			-1, &ctx->insert_acct, NULL) != SQLITE_OK) {

		sqlite_deinit(&ctx);
		printf("Failed to prepare statement\n");
		return NULL;
	}

	return ctx;
}

static int
get_eap_user(void *c, const u8 *identity, size_t identity_len, int phase2, struct eap_user *user)
{
	if (user == NULL)
		return 0;

	os_memset(user, 0, sizeof(*user));
	user->force_version = -1;

	if (!phase2) {
		user->methods[0].vendor = EAP_VENDOR_IETF;
		user->methods[0].method = EAP_TYPE_PEAP;
		return 0;
	}

	if (identity == NULL || identity_len <= 0) {
		printf("request for user without identity for phase2");
		return -1;
	}

	int res = -1;
	struct sqlite_ctx *ctx = c;
	sqlite3_reset(ctx->select_user);

	if (sqlite3_bind_text(ctx->select_user, 1, (char*)identity, (int)identity_len, SQLITE_TRANSIENT) == SQLITE_OK &&
			sqlite3_step(ctx->select_user) == SQLITE_ROW) {

		const unsigned char *password = sqlite3_column_text(ctx->select_user, 1);
		int password_len = sqlite3_column_bytes(ctx->select_user, 1);

		if(password && password_len > 0) {
			user->password = (u8 *) os_strdup((const char *) password);
			user->password_len = (size_t) password_len;
			user->methods[0].vendor = EAP_VENDOR_IETF;
			user->methods[0].method = EAP_TYPE_MSCHAPV2;
			user->accept_attr = &interim_update_attr;
			res = 0;
		}
	}

	sqlite3_reset(ctx->select_user);
	sqlite3_clear_bindings(ctx->select_user);

	return res;
}

static void
bind_radius_int32_attr(sqlite3_stmt *stmt, const char *name, struct radius_msg *msg, u8 attr)
{
	int index = sqlite3_bind_parameter_index(stmt, name);
	if (index == 0) {
		printf("statement has no parameter '%s'\n", name);
		return;
	}

	u32 value;
	if (radius_msg_get_attr_int32(msg, attr, &value) != 0)
		sqlite3_bind_null(stmt, index);
	else
		sqlite3_bind_int(stmt, index, value);
}

static void
bind_radius_string_attr(sqlite3_stmt *stmt, const char *name, struct radius_msg *msg, u8 attr)
{
	int index = sqlite3_bind_parameter_index(stmt, name);
	if (index == 0) {
		printf("statement has no parameter '%s'\n", name);
		return;
	}

	u8 *str;
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

	u32 type;
	if (radius_msg_get_attr_int32(msg, RADIUS_ATTR_ACCT_STATUS_TYPE, &type) != 0 ||
			(type != RADIUS_ACCT_STATUS_TYPE_START &&
					type != RADIUS_ACCT_STATUS_TYPE_STOP &&
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
		printf("inserting accounting data failed!\n");

	sqlite3_reset(stmt);
	sqlite3_clear_bindings(stmt);
}

static void
auth_reply(void *c, struct radius_msg *request, struct radius_msg *reply)
{
	struct sqlite_ctx *ctx = c;
	u8 code = radius_msg_get_hdr(reply)->code;

	if (code != RADIUS_CODE_ACCESS_REJECT && code != RADIUS_CODE_ACCESS_ACCEPT)
		return;

	if (!request || !reply) {
		printf("Invalid request-reply pair (%p, %p)\n", request, reply);
		return;
	}

	printf("===== REQUEST =====\n");
	radius_msg_dump(request);
	printf("===== REPLY =====\n");
	radius_msg_dump(reply);

	UNUSED(ctx);
}

int
main(int argc, char *argv[])
{
	struct radius_server_conf config = {0};

	config.auth_port = AUTH_PORT;
	config.acct_port = ACCT_PORT;
	config.client_file = append_prefix(CLIENT_FILE);
	config.server_id = SERVER_ID;
	config.get_eap_user = get_eap_user;
	config.acct_update = acct_update;
	config.auth_reply = auth_reply;

	if (getenv("DEBUG") && atoi(getenv("DEBUG")))
		wpa_debug_level = MSG_MSGDUMP;
	else
        wpa_debug_level = MSG_INFO;

	config.conf_ctx = sqlite_init();
	if (!config.conf_ctx) {
		printf("Failed to initialize sqlite\n");
		return -1;
	}

	if (os_program_init())
		return -1;

	hostapd_logger_register_cb(hostapd_logger_cb);

	if (eloop_init()) {
		printf("Failed to initialize event loop\n");
		return -1;
	}

	register_methods();
	config.ssl_ctx = init_tls();

	if(!config.ssl_ctx) {
		printf("Failed to initialize ssl context\n");
		return -1;
	}

	struct radius_server_data *srv = radius_server_init(&config);

	eloop_run();

	radius_server_deinit(srv);
	tls_deinit(config.ssl_ctx);
	sqlite_deinit((struct sqlite_ctx **) &config.conf_ctx);

	eloop_destroy();
	os_program_deinit();

	return 0;
}
