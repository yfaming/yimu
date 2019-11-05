#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "socks5_protocol.h"
#include "socks5_no_auth_authenticator.h"

static int no_auth_authenticate(struct authenticator *authenticator);
static int no_auth_poll_input(struct authenticator *authenticator);
static int no_auth_flush_output(struct authenticator *authenticator);
static void no_auth_inner_free(void *inner);

struct authenticator *no_auth_authenticator_new(struct bufferevent *underlying_bev)
{
    struct authenticator_imp imp = {
        no_auth_authenticate,
        no_auth_poll_input,
        no_auth_flush_output,
        no_auth_inner_free,
    };
    return authenticator_new(SOCKS5_AUTH_METHOD_NO_AUTH_REQUIRED, imp, NULL/*inner*/, underlying_bev);
}

static int no_auth_authenticate(struct authenticator *authenticator)
{
    (void)authenticator;
    return YM_AUTH_SUCCESS;
}

static int no_auth_poll_input(struct authenticator *authenticator)
{
    return bufferevent_read_buffer(authenticator->underlying_bev, authenticator->input);
}

static int no_auth_flush_output(struct authenticator *authenticator)
{
    return bufferevent_write_buffer(authenticator->underlying_bev, authenticator->output);
}

static void no_auth_inner_free(void *inner)
{
    (void)inner;
    return; /* nothing to do */
}
