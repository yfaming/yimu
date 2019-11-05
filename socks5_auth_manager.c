#include <stdlib.h>
#include <string.h>

#include <event2/bufferevent.h>

#include "logging.h"
#include "socks5_username_password_authenticator.h"
#include "socks5_auth_manager.h"

/* This is a very naive implementation to support more than one auth methods. */

struct s5auth_manager *s5auth_manager_new()
{
    struct s5auth_manager *s5auth_manager = malloc(sizeof(struct s5auth_manager));
    if (s5auth_manager == NULL) {
        error("malloc for struct s5auth_manager failed: %s (errno=%d)", strerror(errno), errno);
        return NULL;
    }
    memset(s5auth_manager, 0, sizeof(*s5auth_manager));
    return s5auth_manager;
}

void s5auth_manager_free(struct s5auth_manager *s5auth_manager)
{
    if (s5auth_manager->identities)
        free(s5auth_manager->identities);
    free(s5auth_manager);
}

int s5auth_manager_register_no_auth_authenticator(struct s5auth_manager *auth_manager)
{
    auth_manager->no_auth_authenticator_enabled = 1;
    return 0;
}

int s5auth_manager_register_username_password_authenticator(struct s5auth_manager *auth_manager,
        struct identity *identities, size_t n)
{
    auth_manager->identities = calloc(n, sizeof(struct identity));
    if (auth_manager->identities == NULL) {
        error("calloc() for struct identity failed: %s (errno=%d)", strerror(errno), errno);
        return -1;
    }
    size_t i;
    for (i = 0; i < n; i++) {
        strcpy(auth_manager->identities[i].username, identities[i].username);
        strcpy(auth_manager->identities[i].password, identities[i].password);
    }
    auth_manager->identities_size = n;
    auth_manager->username_password_authenticator_enabled = 1;
    return 0;
}


static size_t s5auth_manager_get_supported_auth_methods(struct s5auth_manager *auth_manager,
        uint8_t auth_methods[], size_t len);
static struct authenticator *s5auth_manager_create_authenticator(struct s5auth_manager *auth_manager,
        uint8_t auth_method, struct bufferevent *underlying_bev);

struct authenticator *s5auth_manager_choose_authenticator(struct s5auth_manager *auth_manager,
        long tunnel_id, const struct s5_auth_negotiation_request *req, struct bufferevent *underlying_bev)
{
    uint8_t supported_methods[256]; /* more than enough */
    size_t len = sizeof(supported_methods) / sizeof(supported_methods[0]);
    size_t n_supported_methods = s5auth_manager_get_supported_auth_methods(auth_manager,
            supported_methods, len);

    uint8_t auth_method = SOCKS5_AUTH_METHOD_NO_ACCEPTABLE_METHOD;
    size_t i, j;
    for (i = 0; i < req->n_methods; i++) {
        for (j = 0; j < n_supported_methods; j++) {
            if (req->methods[i] == supported_methods[j]) {
                auth_method = req->methods[i];
            }
        }
    }
    debug("tunnel#%ld auth_method=%d is chosen", tunnel_id, auth_method);
    if (auth_method == SOCKS5_AUTH_METHOD_NO_ACCEPTABLE_METHOD)
        return NULL;
    else
        return s5auth_manager_create_authenticator(auth_manager, auth_method, underlying_bev);
}

static size_t s5auth_manager_get_supported_auth_methods(struct s5auth_manager *auth_manager,
        uint8_t auth_methods[], size_t len)
{
    size_t i = 0;
    if (auth_manager->username_password_authenticator_enabled && i < len)
        auth_methods[i++] = SOCKS5_AUTH_METHOD_USERNAME_PASSWORD;
    if (auth_manager->no_auth_authenticator_enabled && i < len)
        auth_methods[i++] = SOCKS5_AUTH_METHOD_NO_AUTH_REQUIRED;

    size_t j = 0;
    for (j = 0; j < i; j++) {
        debug("supported_auth_method[%zu]=%d", j, auth_methods[j]);
    }

    return i;
}


static struct authenticator *s5auth_manager_create_authenticator(struct s5auth_manager *auth_manager,
        uint8_t auth_method, struct bufferevent *underlying_bev)
{
    struct authenticator *res = NULL;
    if (auth_method == SOCKS5_AUTH_METHOD_USERNAME_PASSWORD) {
        assert(auth_manager->username_password_authenticator_enabled);
        res = username_password_authenticator_new(underlying_bev, auth_manager->identities, auth_manager->identities_size);
    } else if (auth_method == SOCKS5_AUTH_METHOD_NO_AUTH_REQUIRED) {
        assert(auth_manager->no_auth_authenticator_enabled);
        res = no_auth_authenticator_new(underlying_bev);
    } else {
        error("auth_method=%d not supported", auth_method);
        return NULL;
    }

    if (res == NULL)
        error("s5auth_manager_create_authenticator() failed: %s (errno=%d)", strerror(errno), errno);
    return res;
}
