#include <errno.h>
#include <stdlib.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "logging.h"
#include "socks5_authenticator.h"


struct authenticator *authenticator_new(uint8_t auth_method,
        struct authenticator_imp ops, void *inner,
        struct bufferevent *underlying_bev)
{
    struct evbuffer *input = evbuffer_new();
    struct evbuffer *output = evbuffer_new();
    struct authenticator *authenticator = NULL;

    if (input == NULL || output == NULL) {
        error("evbuffer_new() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }

    authenticator = malloc(sizeof(struct authenticator));
    if (authenticator == NULL) {
        error("malloc() for authenticator failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }
    authenticator->auth_method = auth_method;
    authenticator->ops = ops;
    authenticator->underlying_bev = underlying_bev;
    authenticator->input = input;
    authenticator->output = output;
    authenticator->inner = inner;
    return authenticator;

FAIL:
    if (authenticator)
        free(authenticator);
    if (input)
        evbuffer_free(input);
    if (output)
        evbuffer_free(output);
    if (inner)
        ops.inner_free(inner);
    return NULL;
}

void authenticator_free(struct authenticator *authenticator)
{
    evbuffer_free(authenticator->input);
    evbuffer_free(authenticator->output);
    authenticator->ops.inner_free(authenticator->inner);
    free(authenticator);
}

int authenticator_do_authenticate(struct authenticator *authenticator)
{
    return authenticator->ops.authenticate(authenticator);
}

struct evbuffer *authenticator_get_input_buffer(struct authenticator *authenticator)
{
    int n = authenticator->ops.poll_input(authenticator);
    if (n == -1) {
        error("authenticator->ops.poll_input failed: %s (errno=%d)", strerror(errno), errno);
        return NULL;
    }
    return authenticator->input;
}

struct evbuffer *authenticator_get_output_buffer(struct authenticator *authenticator)
{
    return authenticator->output;
}


int authenticator_flush(struct authenticator *authenticator)
{
    return authenticator->ops.flush_output(authenticator);
}
