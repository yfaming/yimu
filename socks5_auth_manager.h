#ifndef SOCKS5_AUTH_MANAGER_H
#define SOCKS5_AUTH_MANAGER_H
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <event2/bufferevent.h>

#include "logging.h"
#include "socks5_authenticator.h"
#include "socks5_no_auth_authenticator.h"
#include "socks5_protocol.h"
#include "socks5_username_password_authenticator.h"

struct s5auth_manager {
    int no_auth_authenticator_enabled;

    int username_password_authenticator_enabled;
    struct identity *identities;
    size_t identities_size;
};

struct s5auth_manager *s5auth_manager_new();
void s5auth_manager_free(struct s5auth_manager *s5auth_manager);

int s5auth_manager_register_no_auth_authenticator(struct s5auth_manager *auth_manager);
int s5auth_manager_register_username_password_authenticator(struct s5auth_manager *auth_manager,
        struct identity *identities, size_t n);


struct authenticator *s5auth_manager_choose_authenticator(struct s5auth_manager *auth_manager,
        long tunnel_id, const struct s5_auth_negotiation_request *req, struct bufferevent *underlying_bev);
#endif /* ifndef SOCKS5_AUTH_MANAGER_H */
