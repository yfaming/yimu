#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include <event2/bufferevent.h>

#include "logging.h"
#include "socks5_conn.h"
#include "socks5_authenticator.h"
#include "util.h"

static void socks5conn_incref(struct socks5conn *socks5conn);
static void socks5conn_decref(struct socks5conn *socks5conn);
static void socks5conn_reset_all_cbs(struct socks5conn *socks5conn);
static void socks5conn_real_free(struct socks5conn *socks5conn);

/* bufferevent callback typedefs
 * typedef void (*bufferevent_data_cb)(struct bufferevent *bev, void *ctx);
 * typedef void (*bufferevent_event_cb)(struct bufferevent *bev, short events, void *ctx);
 */
/* readcb for underlying bufferevent */
static void socks5conn_readcb(struct bufferevent *bev, void *user_arg);
static void socks5conn_writecb(struct bufferevent *bev, void *user_arg);
static void socks5conn_event_cb(struct bufferevent *bev, short events, void *user_arg);


/* convert bufferevent event to string, keep length of s >= 128 */
char *str_bufferevent_event(int event, char *s, size_t len);

struct socks5tunnel;

struct socks5conn {
    enum socks5_stage stage;
    struct bufferevent *bev;
    int write_is_shutdown;

    /* We duplicate tunnel's id to avoid mutual dependency between socks5conn and socks5tunnel */
    long tunnel_id;
    struct socks5tunnel *tunnel;

    struct authenticator *authenticator;

    int refcnt;

    /* callbacks */
    socks5conn_on_eof_cb on_eof_cb;
    socks5conn_on_read_error_cb on_read_error_cb;
    socks5conn_on_write_error_cb on_write_error_cb;
    socks5conn_on_write_completed_cb on_write_completed_cb;

    socks5conn_on_auth_negotiation_req_cb on_auth_negotiation_req_cb;
    socks5conn_on_auth_success_cb on_auth_success_cb;
    socks5conn_on_auth_error_cb on_auth_error_cb;
    socks5conn_on_s5_request_cb on_s5_request_cb;
    socks5conn_on_data_cb on_data_cb;
};

struct socks5conn *socks5conn_new(struct event_base *evbase, evutil_socket_t connfd)
{
    struct bufferevent *bev = NULL;
    struct socks5conn *conn = NULL;

    bev = bufferevent_socket_new(evbase, connfd, BEV_OPT_CLOSE_ON_FREE);
    if (bev == NULL) {
        error("bufferevent_socket_new() failed: %s (errno=%d)", strerror(errno), errno);
        close(connfd);
        goto FAIL;
    }

    conn = malloc(sizeof(struct socks5conn));
    if (conn == NULL) {
        error("malloc() for socks5conn failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }
    conn->stage = SOCKS5_STAGE_NEGOTIATION;
    conn->bev = bev;
    conn->write_is_shutdown = 0;
    conn->tunnel_id = 0;
    conn->tunnel = NULL;
    conn->authenticator = NULL;
    conn->refcnt = 1;

    /* callbacks */
    conn->on_eof_cb = NULL;
    conn->on_read_error_cb = NULL;
    conn->on_write_error_cb = NULL;
    conn->on_write_completed_cb = NULL;

    conn->on_auth_negotiation_req_cb = NULL;
    conn->on_auth_success_cb = NULL;
    conn->on_auth_error_cb = NULL;
    conn->on_s5_request_cb = NULL;
    conn->on_data_cb = NULL;

    /* set callbacks for bev */
    bufferevent_setcb(bev, socks5conn_readcb, socks5conn_writecb, socks5conn_event_cb, conn);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    return conn;

FAIL:
    if (conn)
        free(conn);
    if (bev)
        bufferevent_free(bev);
    return NULL;
}

void socks5conn_free(struct socks5conn *socks5conn)
{
    socks5conn_reset_all_cbs(socks5conn);
    socks5conn_decref(socks5conn);
}

static void socks5conn_incref(struct socks5conn *socks5conn)
{
    socks5conn->refcnt++;
}

static void socks5conn_decref(struct socks5conn *socks5conn)
{
    socks5conn->refcnt--;
    if (socks5conn->refcnt == 0)
        socks5conn_real_free(socks5conn);
}

static void socks5conn_reset_all_cbs(struct socks5conn *socks5conn)
{
    socks5conn->on_eof_cb = NULL;
    socks5conn->on_read_error_cb = NULL;
    socks5conn->on_write_error_cb = NULL;
    socks5conn->on_write_completed_cb = NULL;
    socks5conn->on_auth_negotiation_req_cb = NULL;
    socks5conn->on_auth_success_cb = NULL;
    socks5conn->on_auth_error_cb = NULL;
    socks5conn->on_s5_request_cb = NULL;
    socks5conn->on_data_cb = NULL;
}

static void socks5conn_real_free(struct socks5conn *socks5conn)
{
    debug("tunnel#%ld, socks5conn close", socks5conn->tunnel_id);
    bufferevent_free(socks5conn->bev);
    if (socks5conn->authenticator)
        authenticator_free(socks5conn->authenticator);
    free(socks5conn);
}



int socks5conn_write_s5_auth_negotiation_reply(struct socks5conn *socks5conn,
        const struct s5_auth_negotiation_reply *res)
{
    assert(socks5conn_get_stage(socks5conn) == SOCKS5_STAGE_NEGOTIATION);
    assert(socks5conn->write_is_shutdown == 0);
    struct evbuffer *output_buffer = bufferevent_get_output(socks5conn->bev);
    return evbuffer_write_s5_auth_negotiation_reply(output_buffer, res);
}

int socks5conn_write_s5_reply(struct socks5conn *socks5conn, const struct s5_reply *res)
{
    assert(socks5conn_get_stage(socks5conn) == SOCKS5_STAGE_REQUEST_PROCESS);
    assert(socks5conn->write_is_shutdown == 0);
    struct authenticator *authenticator = socks5conn->authenticator;
    assert(authenticator != NULL);
    struct evbuffer *output_buffer = authenticator_get_output_buffer(authenticator);

    if (evbuffer_write_s5_reply(output_buffer, res) == YM_ERROR) {
        error("evbuffer_write_s5_reply failed: %s (errno=%d)", strerror(errno), errno);
        return YM_ERROR;
    }

    if (authenticator_flush(authenticator) == -1)
        return YM_ERROR;
    else
        return YM_SUCCESS;
}

int socks5conn_write_data(struct socks5conn *socks5conn, struct evbuffer *buffer)
{
    assert(socks5conn_get_stage(socks5conn) == SOCKS5_STAGE_PROXY);
    assert(socks5conn->write_is_shutdown == 0);
    struct authenticator *authenticator = socks5conn->authenticator;
    assert(authenticator != NULL);
    struct evbuffer *output_buffer = authenticator_get_output_buffer(authenticator);

    if (evbuffer_add_buffer(output_buffer, buffer) == -1) {
        error("evbuffer_add_buffer failed: %s (errno=%d)", strerror(errno), errno);
        return YM_ERROR;
    }

    if (authenticator_flush(authenticator) == -1)
        return YM_ERROR;
    else
        return YM_SUCCESS;
}

void socks5conn_set_tunnel(struct socks5conn *conn, struct socks5tunnel *tunnel, long tunnel_id)
{
    conn->tunnel_id = tunnel_id;
    conn->tunnel = tunnel;
}

enum socks5_stage socks5conn_get_stage(struct socks5conn *socks5conn)
{
    return socks5conn->stage;
}

void socks5conn_set_stage(struct socks5conn *socks5conn, enum socks5_stage stage)
{
    socks5conn->stage = stage;
}

int socks5conn_getpeername(struct socks5conn *socks5conn, struct sockaddr *addr, socklen_t *addrlen)
{
    return getpeername(bufferevent_getfd(socks5conn->bev), addr, addrlen);
}


struct authenticator * socks5conn_choose_authenticator(struct socks5conn *socks5conn,
        struct s5auth_manager *auth_manager, const struct s5_auth_negotiation_request *req)
{
    socks5conn->authenticator = s5auth_manager_choose_authenticator(auth_manager,
            socks5conn->tunnel_id, req, socks5conn->bev);
    return socks5conn->authenticator;
}

int socks5conn_stop_read(struct socks5conn *socks5conn)
{
    return bufferevent_disable(socks5conn->bev, EV_READ);
}

void socks5conn_shutdown_write(struct socks5conn *socks5conn)
{
    /* just set a flag, will call shutdown(2) when out buffer is emptied */
    socks5conn->write_is_shutdown = 1;
}



void socks5conn_set_on_eof_cb(struct socks5conn *socks5conn, socks5conn_on_eof_cb cb)
{
    socks5conn->on_eof_cb = cb;
}

void socks5conn_set_on_read_error_cb(struct socks5conn *socks5conn, socks5conn_on_read_error_cb cb)
{
    socks5conn->on_read_error_cb = cb;
}

void socks5conn_set_on_write_error_cb(struct socks5conn *socks5conn, socks5conn_on_write_error_cb cb)
{
    socks5conn->on_write_error_cb = cb;
}

void socks5conn_set_on_write_completed_cb(struct socks5conn *socks5conn, socks5conn_on_write_completed_cb cb)
{
    socks5conn->on_write_completed_cb = cb;
}

void socks5conn_set_on_auth_negotiation_req_cb(struct socks5conn *socks5conn,
    socks5conn_on_auth_negotiation_req_cb cb)
{
    socks5conn->on_auth_negotiation_req_cb = cb;
}

void socks5conn_set_on_auth_success_cb(struct socks5conn *socks5conn, socks5conn_on_auth_success_cb cb)
{
    socks5conn->on_auth_success_cb = cb;
}

void socks5conn_set_on_auth_error_cb(struct socks5conn *socks5conn, socks5conn_on_auth_error_cb cb)
{
    socks5conn->on_auth_error_cb = cb;
}

void socks5conn_set_on_s5_request_cb(struct socks5conn *socks5conn, socks5conn_on_s5_request_cb cb)
{
    socks5conn->on_s5_request_cb = cb;
}

void socks5conn_set_on_data_cb(struct socks5conn *socks5conn, socks5conn_on_data_cb cb)
{
    socks5conn->on_data_cb = cb;
}



static void socks5conn_readcb(struct bufferevent *bev, void *user_arg)
{
    (void)bev;
    struct socks5conn *socks5conn = user_arg;
    socks5conn_incref(socks5conn);

    enum socks5_stage stage = socks5conn->stage;
    struct evbuffer *input_buffer = NULL;

    int n = 0;
    if (stage == SOCKS5_STAGE_NEGOTIATION) {
        input_buffer = bufferevent_get_input(socks5conn->bev);
        struct s5_auth_negotiation_request auth_negotiation_req;
        n = evbuffer_read_s5_auth_negotiation_request(input_buffer, &auth_negotiation_req);
        if (n == YM_SUCCESS) {
            for(n = 0; n < auth_negotiation_req.n_methods; n++) {
                debug("tunnel#%ld auth_negotiation_req.methods[%d]=%d",
                        socks5conn->tunnel_id, n, auth_negotiation_req.methods[n]);
            }
            if (socks5conn->on_auth_negotiation_req_cb)
                socks5conn->on_auth_negotiation_req_cb(socks5conn->tunnel, &auth_negotiation_req);
        } else if (n == YM_ERROR) {
            error("evbuffer_read_s5_auth_negotiation_request failed: %s (errno=%d)",
                    strerror(errno), errno);
            if (socks5conn->on_read_error_cb)
                socks5conn->on_read_error_cb(socks5conn->tunnel);
        } else {
            /* YM_NEED_MORE_DATA: nothing to do */
        }
    } else if (stage == SOCKS5_STAGE_AUTHENTICATION) {
        /* In stage SOCKS5_STAGE_AUTHENTICATION, authenticator takes care of everything. In stage
         * SOCKS5_STAGE_REQUEST_PROCESS and SOCKS5_STAGE_PROXY, authenticator acts like "transport",
         * we do not read/write directly with soks5conn
         */
        assert(socks5conn->authenticator != NULL);
        n = authenticator_do_authenticate(socks5conn->authenticator);
        if (n == YM_AUTH_SUCCESS) {
            if (socks5conn->on_auth_success_cb)
                socks5conn->on_auth_success_cb(socks5conn->tunnel);
        } else if (n == YM_AUTH_ERROR) {
            debug("tunnel#%ld authentication failed", socks5conn->tunnel_id);
            if (socks5conn->on_auth_error_cb)
                socks5conn->on_auth_error_cb(socks5conn->tunnel);
        } else { /* YM_AUTH_PENDING */
            /* do nothing, wait for more data */
            debug("tunnel#%ld authentication result: YM_AUTH_PENDING", socks5conn->tunnel_id);
        }

    } else if (stage == SOCKS5_STAGE_REQUEST_PROCESS) {
        assert(socks5conn->authenticator != NULL);
        debug("tunnel#%ld stage: SOCKS5_STAGE_REQUEST_PROCESS", socks5conn->tunnel_id);
        input_buffer = authenticator_get_input_buffer(socks5conn->authenticator);
        if (input_buffer == NULL) {
            if (socks5conn->on_read_error_cb)
                socks5conn->on_read_error_cb(socks5conn->tunnel);
        } else {
            struct s5_request s5req;
            uint8_t reply_code;
            n = evbuffer_read_s5_request(input_buffer, &s5req, &reply_code);
            if (n == YM_SUCCESS) {
                char *str_req = strs5request(&s5req);
                debug("tunnel#%ld, %s", socks5conn->tunnel_id, str_req);
                free(str_req);
                if (socks5conn->on_s5_request_cb)
                    socks5conn->on_s5_request_cb(socks5conn->tunnel, &s5req);
            } else if (n == YM_ERROR) {
                error("evbuffer_read_s5_request failed: %s (errno=%d)", strerror(errno), errno);
                if (socks5conn->on_read_error_cb)
                    socks5conn->on_read_error_cb(socks5conn->tunnel);
            } else {
                /* YM_NEED_MORE_DATA: nothing to do */
            }
        }

    } else { /* SOCKS5_STAGE_PROXY */
        assert(socks5conn->stage == SOCKS5_STAGE_PROXY);
        assert(socks5conn->authenticator != NULL);

        input_buffer = authenticator_get_input_buffer(socks5conn->authenticator);
        if (input_buffer == NULL) {
            if (socks5conn->on_read_error_cb)
                socks5conn->on_read_error_cb(socks5conn->tunnel);
        } else {
            if (socks5conn->on_data_cb)
                socks5conn->on_data_cb(socks5conn->tunnel, input_buffer);
        }
    }

    socks5conn_decref(socks5conn);
}

static void socks5conn_writecb(struct bufferevent *bev, void *user_arg)
{
    struct socks5conn *socks5conn = user_arg;
    socks5conn_incref(socks5conn);

    struct evbuffer *output_buffer = bufferevent_get_output(bev);
    if (evbuffer_get_length(output_buffer) == 0) {
        if (socks5conn->write_is_shutdown) {
            /* do real shutdown only when buffer is emptied */
            int n = shutdown(bufferevent_getfd(socks5conn->bev), SHUT_WR);
            if (n == -1)
                error("tunnel#%ld shutdown() failed: %s (errno=%d)",
                        socks5conn->tunnel_id, strerror(errno), errno);
        }

        if (socks5conn->on_write_completed_cb != NULL) {
            socks5conn->on_write_completed_cb(socks5conn->tunnel);
        }
    }

    socks5conn_decref(socks5conn);
}

static void socks5conn_event_cb(struct bufferevent *bev, short event, void *user_arg)
{
    (void)bev;
    struct socks5conn *socks5conn = user_arg;
    socks5conn_incref(socks5conn);

    char eventstr[128];
    str_bufferevent_event(event, eventstr, sizeof(eventstr));
    debug("tunnel#%ld, socks5conn event: %s", socks5conn->tunnel_id, eventstr);

    if (event & BEV_EVENT_EOF) {
        if (socks5conn->on_eof_cb)
            socks5conn->on_eof_cb(socks5conn->tunnel);
    }
    if (event & BEV_EVENT_ERROR) {
        debug("tunnel#%ld socket error: %s", socks5conn->tunnel_id, strerror(EVUTIL_SOCKET_ERROR()));
        if (event & BEV_EVENT_READING) {
            if (socks5conn->on_read_error_cb)
                socks5conn->on_read_error_cb(socks5conn->tunnel);
        } else
            if (socks5conn->on_write_error_cb)
                socks5conn->on_write_error_cb(socks5conn->tunnel);
    }
    /* no possible: BEV_EVENT_TIMEOUT or BEV_EVENT_CONNECTED */

    socks5conn_decref(socks5conn);
}
