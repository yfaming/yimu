#ifndef SOCKS5_AUTHENTICATOR_H
#define SOCKS5_AUTHENTICATOR_H

#include <event2/buffer.h>

#include "logging.h"

/* Current authentication mechanism is not generic enough.
 * 1)To support ANY authentication, the API should be totally event based. We should provide
 * on_authentication_success/on_authentication_error callbacks, not authenticator_do_authenticate.
 * 2)To support encryption/decryption for UDP association, we should expose codec API.
 */

/*
 * According to RFC 1928, during SOCKS5_STAGE_AUTHENTICATION(akka method-specific sub-negotiation),
 * the client and server may do arbitary data exchange depending on the selected auth method.
 *
 * And when authentication finished, "If the negotiated method includes encapsulation for purposes
 * of integrity checking and/or confidentiality", the data "MUST be encapsulated in the method-
 * dependent encapsulation".
 * Therefore, during SOCKS5_STAGE_REQUEST_PROCESS and SOCKS5_STAGE_PROXY,
 * authenticator is like a "transport", it performs read/write operation with underlying socket
 * and may need to do decode/encode or encrypt/decrypt works.
 */

enum {
    YM_AUTH_SUCCESS,
    YM_AUTH_ERROR,
    YM_AUTH_PENDING, /* authentication not finished */
};

struct authenticator; /* forward declaration */

/* authenticator_imp encapsulates the implementation detail a concrete authenticator.
 * authenticate is used in SOCKS5_STAGE_AUTHENTICATION to authenticate the client.
 * poll_input and flush_putput is used in SOCKS5_STAGE_REQUEST_PROCESS and SOCKS5_STAGE_PROXY
 * when authenticator acts as IO transport.
 */
struct authenticator_imp {
    /* authenticate implements the authentication logic, it returns YM_AUTH_SUCCESS, YM_AUTH_ERROR
     * or YM_AUTH_PENDING */
    int (*authenticate)(struct authenticator *authenticator);

    /* poll_input polls(reads) data from underlying bufferevent to authenticator's input
     * evbuffer. Decode/decrpt/verification operations can be done in this method.
     * It returns 0 on success, -1 on failure.
     */
    int (*poll_input)(struct authenticator *authenticator);
    /* flush_putput flushes data from authenticator's output evbuffer to underlying
     * bufferevent. Encode/encrypt/verification operations can be done in this method.
     */
    int (*flush_output)(struct authenticator *authenticator);

    /* release resourses inner points to */
    void (*inner_free)(void *inner);
};

/* definition of struct authenticator is exposed, to save some getter/setter methods.
 * Regular user other than concrete authenticator implementor, should not access its fields directly.
 */
struct authenticator {
    uint8_t auth_method;
    struct authenticator_imp ops;
    struct bufferevent *underlying_bev;
    struct evbuffer *input;  /* input evbuffer */
    struct evbuffer *output; /* output evbuffer */

    /* inner represents arbitary data/state an authenticator needs to get job done. It might be a
     * pointer to a struct. */
    void *inner;
};

/* below are public APIs authenticator exposes */

struct authenticator *authenticator_new(uint8_t auth_method,
        struct authenticator_imp ops, void *inner,
        struct bufferevent *underlying_bev);
void authenticator_free(struct authenticator *authenticator);

/* authenticator_do_authenticate do authentication. It will return YM_AUTH_SUCCESS,
 * YM_AUTH_ERROR or YM_AUTH_PENDING.
 */
int authenticator_do_authenticate(struct authenticator *authenticator);

/* Get authenticator's input and output buffer. These are the buffers we directly use. */
struct evbuffer *authenticator_get_input_buffer(struct authenticator *authenticator);
struct evbuffer *authenticator_get_output_buffer(struct authenticator *authenticator);

/* authenticator_flush flushes data from authenticator's output evbuffer to underlying bufferevent.
 * It returns 0 on success, -1 on error.
 * We should invoke this method whenever we've done writing data.
 */
int authenticator_flush(struct authenticator *authenticator);

#endif /* ifndef SOCKS5_AUTHENTICATOR_H */
