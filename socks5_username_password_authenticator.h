#ifndef USERNAME_PASSWORD_AUTHENTICATOR
#define USERNAME_PASSWORD_AUTHENTICATOR

#include "socks5_authenticator.h"

/* username_password_authenticator, the authenticator use username and password to do
 * authentication.
 * The authentication process is specified in RFC 1929.
 */

struct identity {
    char username[255];
    char password[255];
};

/* create a username_password_authenticator with predefined identities. */
struct authenticator *username_password_authenticator_new(struct bufferevent *underlying_bev,
        struct identity *identities, size_t len);

#endif /* ifndef USERNAME_PASSWORD_AUTHENTICATOR */
