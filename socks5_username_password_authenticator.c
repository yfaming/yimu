#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "logging.h"
#include "socks5_protocol.h"
#include "socks5_username_password_authenticator.h"

struct username_password_authenticator_inner {
    struct identity *identities;
    size_t size;
};
static int authenticate_username_password(struct username_password_authenticator_inner *inner,
        const char *username, const char *password);

static int username_password_authenticate(struct authenticator *authenticator);
static int username_password_poll_input(struct authenticator *authenticator);
static int username_password_flush_output(struct authenticator *authenticator);
static void username_password_inner_free(void *inner);

struct authenticator *username_password_authenticator_new(struct bufferevent *underlying_bev,
        struct identity *identities, size_t n)
{
    struct username_password_authenticator_inner *inner = NULL;
    inner = malloc(sizeof(struct username_password_authenticator_inner));
    if (inner == NULL) {
        error("malloc() for struct username_password_authenticator_inner failed: %s (errno=%d)",
                strerror(errno), errno);
        return NULL;
    }

    inner->identities = calloc(n, sizeof(struct identity));
    if (inner == NULL) {
        error("calloc() for struct identity failed: %s (errno=%d)", strerror(errno), errno);
        free(inner);
        return NULL;
    }
    size_t i;
    for (i = 0; i < n; i++) {
        strcpy(inner->identities[i].username, identities[i].username);
        strcpy(inner->identities[i].password, identities[i].password);
    }
    inner->size = n;

    struct authenticator_imp imp = {
        username_password_authenticate,
        username_password_poll_input,
        username_password_flush_output,
        username_password_inner_free,
    };
    return authenticator_new(SOCKS5_AUTH_METHOD_USERNAME_PASSWORD, imp, inner, underlying_bev);
}

static int authenticate_username_password(struct username_password_authenticator_inner *inner,
        const char *username, const char *password)
{
    size_t i;
    for (i = 0; i < inner->size; i++) {
        if (strcmp(inner->identities[i].username, username) == 0
            && strcmp(inner->identities[i].password, password) == 0) {
                return YM_AUTH_SUCCESS;
            }
    }
    return YM_AUTH_ERROR;
}

#define SOCKS5_USERNAME_PASSWORD_AUTH_V1 1

struct s5_auth_username_password_request {
    uint8_t version;
    uint8_t username_len;
    char username[256];
    uint8_t password_len;
    char password[256];
};

#define SOCKS5_USERNAME_PASSWORD_AUTH_STATUS_SUCCESS 0
#define SOCKS5_USERNAME_PASSWORD_AUTH_STATUS_FAILURE 1
struct s5_auth_username_password_reply {
    uint8_t version;
    uint8_t status;
};

static int evbuffer_read_s5_auth_username_password_request(struct evbuffer *buffer,
    struct s5_auth_username_password_request *req)
{
    size_t buflen = evbuffer_get_length(buffer);
    if (buflen < 2)
        return YM_NEED_MORE_DATA;

    uint8_t *ptr = evbuffer_pullup(buffer, 2);
    uint8_t ver = ptr[0];
    uint8_t username_len = ptr[1];
    if (buflen < 3 + username_len)
        return YM_NEED_MORE_DATA;

    ptr = evbuffer_pullup(buffer, 3 + username_len);
    uint8_t password_len = ptr[2 + username_len];
    uint8_t req_len = 3 + username_len + password_len;
    if (buflen < req_len)
        return YM_NEED_MORE_DATA;

    ptr = evbuffer_pullup(buffer, req_len);
    req->version = ver;
    req->username_len = username_len;
    strncpy(req->username, (char *)ptr + 2, username_len);
    req->username[username_len] = '\0';

    req->password_len = password_len;
    strncpy(req->password, (char *)ptr + 3 + username_len, password_len);
    req->password[password_len] = '\0';

    evbuffer_drain(buffer, req_len);
    return YM_SUCCESS;
}

static int evbuffer_write_s5_auth_username_password_reply(struct evbuffer *buffer,
    struct s5_auth_username_password_reply *res)
{
    if (evbuffer_add(buffer, &res->version, sizeof(res->version)) != 0)
        return YM_ERROR;
    if (evbuffer_add(buffer, &res->status, sizeof(res->status)) != 0)
        return YM_ERROR;
    debug("evbuffer_write_s5_auth_username_password_reply: YM_SUCCESS");
    return YM_SUCCESS;
}

static int username_password_authenticate(struct authenticator *authenticator)
{
    debug("username_password_authenticate");
    struct s5_auth_username_password_request req;
    struct s5_auth_username_password_reply res;
    res.version = SOCKS5_USERNAME_PASSWORD_AUTH_V1;

    /* FIXME: ugly code... */
    struct evbuffer *input = authenticator_get_input_buffer(authenticator);
    int n = evbuffer_read_s5_auth_username_password_request(input, &req);
    if (n == YM_NEED_MORE_DATA)
        return YM_AUTH_PENDING;
    else if (n == YM_ERROR) {
        error("evbuffer_read_s5_auth_negotiation_request() failed:%s (errno=%d)",
                strerror(errno), errno);
        res.status = SOCKS5_USERNAME_PASSWORD_AUTH_STATUS_FAILURE;
    } else { /* YM_SUCCESS */
        n = authenticate_username_password(authenticator->inner, req.username, req.password);
        if (n == YM_ERROR)
            res.status = SOCKS5_USERNAME_PASSWORD_AUTH_STATUS_FAILURE;
        else
            res.status = SOCKS5_USERNAME_PASSWORD_AUTH_STATUS_SUCCESS;
    }

    struct evbuffer *output = authenticator_get_output_buffer(authenticator);
    if (evbuffer_write_s5_auth_username_password_reply(output, &res) == YM_ERROR)
        return YM_ERROR;
    if (authenticator_flush(authenticator) == YM_ERROR)
        return YM_ERROR;

    if (res.status == SOCKS5_USERNAME_PASSWORD_AUTH_STATUS_SUCCESS)
        return YM_SUCCESS;
    else
        return YM_ERROR;
}

static int username_password_poll_input(struct authenticator *authenticator)
{
    return bufferevent_read_buffer(authenticator->underlying_bev, authenticator->input);
}

static int username_password_flush_output(struct authenticator *authenticator)
{
    return bufferevent_write_buffer(authenticator->underlying_bev, authenticator->output);
}

static void username_password_inner_free(void *inner)
{
    struct username_password_authenticator_inner *realinner = inner;
    free(realinner->identities);
    free(realinner);
}
