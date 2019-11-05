#ifndef SOCKS5_NO_AUTH_AUTHENTICATOR_H
#define SOCKS5_NO_AUTH_AUTHENTICATOR_H

#include "socks5_authenticator.h"

/* no_auth_authenticator, the authenticator corresponding to SOCKS5_AUTH_METHOD_NO_AUTH_REQUIRED.
 * It actully does no authentication, and authenticate method always returns YM_AUTH_SUCCESS.
 * It neither performs decode/encode or encrypt/decrypt works.
 */
struct authenticator *no_auth_authenticator_new(struct bufferevent *underlying_bev);

#endif /* ifndef SOCKS5_NO_AUTH_AUTHENTICATOR_H */
