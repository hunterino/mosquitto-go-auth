#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

// Plugin API v5 support
#if MOSQ_AUTH_PLUGIN_VERSION >= 5
#include <mosquitto_plugin_v5.h>
#endif

#if MOSQ_AUTH_PLUGIN_VERSION >= 3
# define mosquitto_auth_opt mosquitto_opt
#endif

#include "go-auth.h"

// Same constants as in go-auth.go
#define AuthRejected 0
#define AuthGranted 1
#define AuthError 2

// Global plugin identifier for v5 API
#if MOSQ_AUTH_PLUGIN_VERSION >= 5
static mosquitto_plugin_id_t *mosq_pid = NULL;
#endif

// ========================================
// Plugin API v5 Callbacks (Mosquitto 2.0+)
// ========================================

#if MOSQ_AUTH_PLUGIN_VERSION >= 5

// Basic authentication callback for v5
static int basic_auth_callback(int event, void *event_data, void *user_data) {
    struct mosquitto_evt_basic_auth *ed = event_data;

    if (!ed->username || !ed->password) {
        return MOSQ_ERR_AUTH;
    }

    const char* clientid = mosquitto_client_id(ed->client);
    if (!clientid) clientid = "";

    GoUint8 ret = AuthUnpwdCheck((char *)ed->username, (char *)ed->password, (char *)clientid);

    switch (ret) {
        case AuthGranted:
            return MOSQ_ERR_SUCCESS;
        case AuthRejected:
            return MOSQ_ERR_AUTH;
        case AuthError:
            return MOSQ_ERR_UNKNOWN;
        default:
            fprintf(stderr, "unknown plugin error: %d\n", ret);
            return MOSQ_ERR_UNKNOWN;
    }
}

// ACL check callback for v5
static int acl_check_callback(int event, void *event_data, void *user_data) {
    struct mosquitto_evt_acl_check *ed = event_data;

    const char* clientid = mosquitto_client_id(ed->client);
    const char* username = mosquitto_client_username(ed->client);
    const char* topic = ed->topic;
    int access = ed->access;

    if (!clientid || !username || !topic || access < 1) {
        return MOSQ_ERR_ACL_DENIED;
    }

    GoUint8 ret = AuthAclCheck((char *)clientid, (char *)username, (char *)topic, access);

    switch (ret) {
        case AuthGranted:
            return MOSQ_ERR_SUCCESS;
        case AuthRejected:
            return MOSQ_ERR_ACL_DENIED;
        case AuthError:
            return MOSQ_ERR_UNKNOWN;
        default:
            fprintf(stderr, "unknown plugin error: %d\n", ret);
            return MOSQ_ERR_UNKNOWN;
    }
}

// Extended authentication start callback for MQTT 5.0
static int extended_auth_start_callback(int event, void *event_data, void *user_data) {
    struct mosquitto_evt_extended_auth *ed = event_data;

    // For now, we don't support extended auth
    // This can be implemented later for OAuth2 flows
    return MOSQ_ERR_NOT_SUPPORTED;
}

// Extended authentication continue callback for MQTT 5.0
static int extended_auth_continue_callback(int event, void *event_data, void *user_data) {
    struct mosquitto_evt_extended_auth *ed = event_data;

    // For now, we don't support extended auth
    // This can be implemented later for OAuth2 flows
    return MOSQ_ERR_NOT_SUPPORTED;
}

#endif // MOSQ_AUTH_PLUGIN_VERSION >= 5

// ========================================
// Plugin API v4 and below (Legacy)
// ========================================

// Version function
int mosquitto_auth_plugin_version(void) {
    #ifdef MOSQ_AUTH_PLUGIN_VERSION
        return MOSQ_AUTH_PLUGIN_VERSION;
    #else
        return 4;
    #endif
}

// Plugin API v5 version function
#if MOSQ_AUTH_PLUGIN_VERSION >= 5
int mosquitto_plugin_version(int supported_version_count, const int *supported_versions) {
    for (int i = 0; i < supported_version_count; i++) {
        if (supported_versions[i] == 5) {
            return 5;
        }
    }
    return 4; // Fall back to v4 if v5 not supported
}
#endif

// Plugin initialization
#if MOSQ_AUTH_PLUGIN_VERSION >= 5
int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data,
                          struct mosquitto_opt *opts, int opt_count) {
    // Store plugin identifier globally
    mosq_pid = identifier;

    // Pass options to Go initialization
    GoInt32 opts_count = opt_count;
    char *keys[opt_count];
    char *values[opt_count];

    for (int i = 0; i < opt_count; i++) {
        keys[i] = opts[i].key;
        values[i] = opts[i].value;
    }

    GoSlice keysSlice = {keys, opt_count, opt_count};
    GoSlice valuesSlice = {values, opt_count, opt_count};

    char versionArray[10];
    sprintf(versionArray, "%i.%i.%i", LIBMOSQUITTO_MAJOR, LIBMOSQUITTO_MINOR, LIBMOSQUITTO_REVISION);

    // Initialize Go plugin
    AuthPluginInit(keysSlice, valuesSlice, opts_count, versionArray);

    // Register callbacks for v5 API
    int rc;

    // Register basic authentication callback
    rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_BASIC_AUTH,
                                     basic_auth_callback, NULL, NULL);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Error registering basic auth callback: %d\n", rc);
        return rc;
    }

    // Register ACL check callback
    rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_ACL_CHECK,
                                     acl_check_callback, NULL, NULL);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Error registering ACL check callback: %d\n", rc);
        return rc;
    }

    // Register extended authentication callbacks (MQTT 5.0)
    rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_EXT_AUTH_START,
                                     extended_auth_start_callback, NULL, NULL);
    if (rc != MOSQ_ERR_SUCCESS && rc != MOSQ_ERR_NOT_SUPPORTED) {
        fprintf(stderr, "Error registering extended auth start callback: %d\n", rc);
        // Non-fatal - extended auth is optional
    }

    rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_EXT_AUTH_CONTINUE,
                                     extended_auth_continue_callback, NULL, NULL);
    if (rc != MOSQ_ERR_SUCCESS && rc != MOSQ_ERR_NOT_SUPPORTED) {
        fprintf(stderr, "Error registering extended auth continue callback: %d\n", rc);
        // Non-fatal - extended auth is optional
    }

    return MOSQ_ERR_SUCCESS;
}

// Plugin cleanup for v5
int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
    // Unregister callbacks
    if (mosq_pid) {
        mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_BASIC_AUTH,
                                      basic_auth_callback, NULL);
        mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_ACL_CHECK,
                                      acl_check_callback, NULL);
        mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_EXT_AUTH_START,
                                      extended_auth_start_callback, NULL);
        mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_EXT_AUTH_CONTINUE,
                                      extended_auth_continue_callback, NULL);
    }

    AuthPluginCleanup();
    return MOSQ_ERR_SUCCESS;
}

#else // Plugin API v4 and below

// Legacy initialization
int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
    GoInt32 opts_count = auth_opt_count;

    char *keys[auth_opt_count];
    char *values[auth_opt_count];
    int i;
    struct mosquitto_auth_opt *o;
    for (i = 0, o = auth_opts; i < auth_opt_count; i++, o++) {
        keys[i] = o->key;
        values[i] = o->value;
    }

    GoSlice keysSlice = {keys, auth_opt_count, auth_opt_count};
    GoSlice valuesSlice = {values, auth_opt_count, auth_opt_count};

    char versionArray[10];
    sprintf(versionArray, "%i.%i.%i", LIBMOSQUITTO_MAJOR, LIBMOSQUITTO_MINOR, LIBMOSQUITTO_REVISION);

    AuthPluginInit(keysSlice, valuesSlice, opts_count, versionArray);
    return MOSQ_ERR_SUCCESS;
}

// Legacy cleanup
int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
    AuthPluginCleanup();
    return MOSQ_ERR_SUCCESS;
}

#endif // Plugin API version check

// Security init/cleanup (used by both v4 and v5)
int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
    return MOSQ_ERR_SUCCESS;
}

// Legacy function-based auth check (v4 and below)
#if MOSQ_AUTH_PLUGIN_VERSION < 5

#if MOSQ_AUTH_PLUGIN_VERSION >= 4
int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password)
#elif MOSQ_AUTH_PLUGIN_VERSION >= 3
int mosquitto_auth_unpwd_check(void *userdata, const struct mosquitto *client, const char *username, const char *password)
#else
int mosquitto_auth_unpwd_check(void *userdata, const char *username, const char *password)
#endif
{
    #if MOSQ_AUTH_PLUGIN_VERSION >= 3
        const char* clientid = mosquitto_client_id(client);
    #else
        const char* clientid = "";
    #endif

    if (username == NULL || password == NULL) {
        printf("error: received null username or password for unpwd check\n");
        fflush(stdout);
        return MOSQ_ERR_AUTH;
    }

    GoUint8 ret = AuthUnpwdCheck((char *)username, (char *)password, (char *)clientid);

    switch (ret) {
        case AuthGranted:
            return MOSQ_ERR_SUCCESS;
        case AuthRejected:
            return MOSQ_ERR_AUTH;
        case AuthError:
            return MOSQ_ERR_UNKNOWN;
        default:
            fprintf(stderr, "unknown plugin error: %d\n", ret);
            return MOSQ_ERR_UNKNOWN;
    }
}

// Legacy function-based ACL check (v4 and below)
#if MOSQ_AUTH_PLUGIN_VERSION >= 4
int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg)
#elif MOSQ_AUTH_PLUGIN_VERSION >= 3
int mosquitto_auth_acl_check(void *userdata, int access, const struct mosquitto *client, const struct mosquitto_acl_msg *msg)
#else
int mosquitto_auth_acl_check(void *userdata, const char *clientid, const char *username, const char *topic, int access)
#endif
{
    #if MOSQ_AUTH_PLUGIN_VERSION >= 3
        const char* clientid = mosquitto_client_id(client);
        const char* username = mosquitto_client_username(client);
        const char* topic = msg->topic;
    #endif

    if (clientid == NULL || username == NULL || topic == NULL || access < 1) {
        printf("error: received null username, clientid or topic, or access is equal or less than 0 for acl check\n");
        fflush(stdout);
        return MOSQ_ERR_ACL_DENIED;
    }

    GoUint8 ret = AuthAclCheck((char *)clientid, (char *)username, (char *)topic, access);

    switch (ret) {
        case AuthGranted:
            return MOSQ_ERR_SUCCESS;
        case AuthRejected:
            return MOSQ_ERR_ACL_DENIED;
        case AuthError:
            return MOSQ_ERR_UNKNOWN;
        default:
            fprintf(stderr, "unknown plugin error: %d\n", ret);
            return MOSQ_ERR_UNKNOWN;
    }
}

#endif // MOSQ_AUTH_PLUGIN_VERSION < 5

// PSK key get (all versions)
#if MOSQ_AUTH_PLUGIN_VERSION >= 4
int mosquitto_auth_psk_key_get(void *user_data, struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
#elif MOSQ_AUTH_PLUGIN_VERSION >= 3
int mosquitto_auth_psk_key_get(void *userdata, const struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
#else
int mosquitto_auth_psk_key_get(void *userdata, const char *hint, const char *identity, char *key, int max_key_len)
#endif
{
    return MOSQ_ERR_AUTH;
}