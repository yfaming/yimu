#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include "logging.h"
#include "socks5_authenticator.h"
#include "socks5_bind_processor.h"
#include "socks5_conn.h"
#include "socks5_protocol.h"
#include "socks5_proxy.h"
#include "socks5_proxy_dummy.h"
#include "socks5_server.h"
#include "socks5_tunnel.h"
#include "socks5_udp_associate_processor.h"
#include "util.h"


static void socks5tunnel_incref(struct socks5tunnel *tunnel);
static void socks5tunnel_decref(struct socks5tunnel *tunnel);
static void socks5tunnel_real_free(struct socks5tunnel *tunnel);


static void socks5tunnel_destroy_on_socks5conn_write_completed(struct socks5tunnel *tunnel);

/* called when socks5conn got EOF */
static void socks5tunnel_on_socks5conn_eof(struct socks5tunnel *tunnel);

/* for socks5conn */
/* called when received auth negotiation request from client */
static void socks5tunnel_on_socks5conn_auth_negotiation_req(struct socks5tunnel *tunnel,
        const struct s5_auth_negotiation_request *req);
/* called when socks5conn authentication succeeded */
static void socks5tunnel_on_socks5conn_auth_success(struct socks5tunnel *tunnel);
/* called when socks5conn authentication failed */
static void socks5tunnel_on_socks5conn_auth_error(struct socks5tunnel *tunnel);

static void socks5tunnel_on_socks5conn_request(struct socks5tunnel *tunnel,
        const struct s5_request *req);
static void socks5tunnel_on_socks5conn_data(struct socks5tunnel *tunnel, struct evbuffer *buffer);

/* for socks5 CMD=CONNECT proxy */
static void socks5tunnel_on_proxy_connection_success(struct socks5tunnel *tunnel,
        const struct sockaddr *addr, socklen_t addrlen);
static void socks5tunnel_on_proxy_connection_error(struct socks5tunnel *tunnel);
static void socks5tunnel_on_proxy_data_received(struct socks5tunnel *tunnel, struct evbuffer *buffer);
static void socks5tunnel_on_proxy_eof(struct socks5tunnel *tunnel);
static void socks5tunnel_on_proxy_read_error(struct socks5tunnel *tunnel);
static void socks5tunnel_on_proxy_write_error(struct socks5tunnel *tunnel);
static void socks5tunnel_on_proxy_data_write_completed(struct socks5tunnel *tunnel);

/* for socks5 CMD=BIND processor */
static void socks5tunnel_on_s5bind_processor_bind_success(struct socks5tunnel *tunnel,
        const struct sockaddr *addr, socklen_t addrlen);
static void socks5tunnel_on_s5bind_processor_bind_error_cb(struct socks5tunnel *tunnel);
static void socks5tunnel_on_s5bind_processor_connection_success_cb(struct socks5tunnel *tunnel,
        const struct sockaddr *addr, socklen_t addrlen);
static void socks5tunnel_on_s5bind_processor_connection_error_cb(struct socks5tunnel *tunnel);
static void socks5tunnel_on_s5bind_processor_data_received_cb(struct socks5tunnel *tunnel,
        struct evbuffer *buffer);
static void socks5tunnel_on_s5bind_processor_data_write_completed_cb(struct socks5tunnel *tunnel);
static void socks5tunnel_on_s5bind_processor_eof_cb(struct socks5tunnel *tunnel);
static void socks5tunnel_on_s5bind_processor_read_error_cb(struct socks5tunnel *tunnel);
static void socks5tunnel_on_s5bind_processor_write_error_cb(struct socks5tunnel *tunnel);

/* for socks5 CMD=UDP_ASSOCIATE processor */
static void socks5tunnel_on_s5udp_associate_processor_success_cb(struct socks5tunnel *tunnel,
        const struct sockaddr *serv_addr, socklen_t addrlen);
static void socks5tunnel_on_s5udp_associate_processor_error_cb(struct socks5tunnel *tunnel);

/* socks5conn; proxyconn */
struct socks5tunnel {
    long id;
    struct socks5server *serv;

    struct socks5conn *socks5conn;
    int socks5conn_eof;
    uint8_t socks5cmd;

    struct proxy *proxy;                     /* only when socks5cmd = SOCKS5_CMD_CONNECT */
    int proxy_eof;
    struct s5bind_processor *bind_processor; /* only when socks5cmd = SOCKS5_CMD_BIND */
    int bind_processor_eof;
    struct s5udp_associate_processor *udp_processor;

    int refcnt;
};

struct socks5tunnel *socks5tunnel_new(struct socks5server *serv, evutil_socket_t connfd,
        struct sockaddr *peeraddr, int addrlen)
{
    (void)addrlen;
    struct socks5conn *socks5conn = NULL;
    struct socks5tunnel *tunnel = NULL;

    socks5conn = socks5conn_new(socks5server_get_event_base(serv), connfd);
    if (socks5conn == NULL) {
        error("socks5conn_new() failed: %s (errno=%d)", strerror(errno), errno);
        close(connfd);
        goto FAIL;
    }

    tunnel = malloc(sizeof(struct socks5tunnel));
    if (tunnel == NULL) {
        error("malloc() for socks5tunnel failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }
    memset(tunnel, 0, sizeof(struct socks5tunnel));

    tunnel->id = socks5server_gen_id(serv);
    tunnel->serv = serv;
    tunnel->socks5conn = socks5conn;
    tunnel->socks5conn_eof = 0;
    tunnel->proxy = NULL;
    tunnel->proxy_eof = 0;
    tunnel->bind_processor = NULL;
    tunnel->bind_processor_eof = 0;
    tunnel->udp_processor = NULL;

    tunnel->refcnt = 1;

    socks5conn_set_tunnel(socks5conn, tunnel, tunnel->id);
    /* set callbacks */
    socks5conn_set_on_eof_cb(socks5conn, socks5tunnel_on_socks5conn_eof);
    /* on read/write error, just destroy the tunnel */
    socks5conn_set_on_read_error_cb(socks5conn, socks5tunnel_free);
    socks5conn_set_on_write_error_cb(socks5conn, socks5tunnel_free);

    socks5conn_set_on_auth_negotiation_req_cb(socks5conn, socks5tunnel_on_socks5conn_auth_negotiation_req);
    socks5conn_set_on_auth_success_cb(socks5conn, socks5tunnel_on_socks5conn_auth_success);
    socks5conn_set_on_auth_error_cb(socks5conn, socks5tunnel_on_socks5conn_auth_error);

    socks5conn_set_on_s5_request_cb(socks5conn, socks5tunnel_on_socks5conn_request);

    char addrstr[SOCKADDR_STRLEN];
    sockaddr_ntop(peeraddr, addrstr, sizeof(addrstr));
    debug("tunnel#%ld created, from %s", tunnel->id, addrstr);
    return tunnel;

FAIL:
    if (tunnel)
        free(tunnel);
    if (socks5conn)
        socks5conn_free(socks5conn);
    return NULL;
}

void socks5tunnel_free(struct socks5tunnel *tunnel)
{
    socks5tunnel_decref(tunnel);
}


static void socks5tunnel_incref(struct socks5tunnel *tunnel)
{
    tunnel->refcnt++;
}

static void socks5tunnel_decref(struct socks5tunnel *tunnel)
{
    tunnel->refcnt--;
    if (tunnel->refcnt == 0)
        socks5tunnel_real_free(tunnel);
}

static void socks5tunnel_real_free(struct socks5tunnel *tunnel)
{
    debug("tunnel#%ld socks5tunnel destroy", tunnel->id);
    socks5conn_free(tunnel->socks5conn);
    if (tunnel->proxy)
        proxy_free(tunnel->proxy);
    if (tunnel->bind_processor)
        s5bind_processor_free(tunnel->bind_processor);
    if (tunnel->udp_processor)
        s5udp_associate_processor_free(tunnel->udp_processor);
    free(tunnel);
}


long socks5tunnel_get_id(struct socks5tunnel *tunnel)
{
    return tunnel->id;
}

static void socks5tunnel_destroy_on_socks5conn_write_completed(struct socks5tunnel *tunnel)
{
    socks5conn_set_on_write_completed_cb(tunnel->socks5conn, socks5tunnel_free);
}

static void socks5tunnel_on_socks5conn_eof(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld: socks5conn EOF", tunnel->id);

    tunnel->socks5conn_eof = 1;
    socks5conn_stop_read(tunnel->socks5conn);
    if (socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_PROXY) {
        if (tunnel->socks5cmd == SOCKS5_CMD_CONNECT) {
            assert(tunnel->proxy != NULL);
            if (tunnel->proxy_eof)
                socks5tunnel_free(tunnel);
            else
                proxy_shutdown_write(tunnel->proxy);
        } else if (tunnel->socks5cmd == SOCKS5_CMD_BIND) {
            assert(tunnel->bind_processor != NULL);
            if (tunnel->bind_processor_eof)
                socks5tunnel_free(tunnel);
            else {
                s5bind_processor_shutdown_write(tunnel->bind_processor);
            }
        } else { /* SOCKS5_CMD_UDP_ASSOCIATE */
            assert(tunnel->socks5cmd == SOCKS5_CMD_UDP_ASSOCIATE);
            assert(tunnel->udp_processor != NULL);
            socks5tunnel_free(tunnel);
        }
    } else {
        /* for other stages, just destroy the tunnel */
        socks5tunnel_free(tunnel);
    }

    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_socks5conn_auth_negotiation_req(struct socks5tunnel *tunnel,
        const struct s5_auth_negotiation_request *req)
{
    socks5tunnel_incref(tunnel);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_NEGOTIATION);
    struct s5auth_manager *auth_manager = socks5server_get_auth_manager(tunnel->serv);
    assert(auth_manager != NULL);
    struct authenticator *authenticator = socks5conn_choose_authenticator(tunnel->socks5conn,
            auth_manager, req);

    struct s5_auth_negotiation_reply res;
    res.version = SOCKS_V5;
    if (req->version == SOCKS_V5 && authenticator)
        res.method = authenticator->auth_method;
    else
        res.method = SOCKS5_AUTH_METHOD_NO_ACCEPTABLE_METHOD;

    int n = socks5conn_write_s5_auth_negotiation_reply(tunnel->socks5conn, &res);
    if (n == YM_SUCCESS) {
        if (res.method == SOCKS5_AUTH_METHOD_NO_ACCEPTABLE_METHOD) {
            /* do nothing, wait for the client to close connection */
        } else {
            /* go to next stage */
            socks5conn_set_stage(tunnel->socks5conn, SOCKS5_STAGE_AUTHENTICATION);
            if (res.method == SOCKS5_AUTH_METHOD_NO_AUTH_REQUIRED)
                socks5conn_set_stage(tunnel->socks5conn, SOCKS5_STAGE_REQUEST_PROCESS);
        }
    } else { /* YM_ERROR */
        error("socks5conn_write_s5_auth_negotiation_reply failed: %s (errno=%d)", strerror(errno), errno);
        socks5tunnel_free(tunnel);
    }
    socks5tunnel_decref(tunnel);
}


static void socks5tunnel_on_socks5conn_auth_success(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld authentication succeeded", tunnel->id);
    socks5conn_set_stage(tunnel->socks5conn, SOCKS5_STAGE_REQUEST_PROCESS);
    socks5tunnel_decref(tunnel);
}


static void socks5tunnel_on_socks5conn_auth_error(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld authentication failed", tunnel->id);
    socks5conn_set_stage(tunnel->socks5conn, SOCKS5_STAGE_REQUEST_PROCESS);
    socks5conn_stop_read(tunnel->socks5conn);
    socks5tunnel_destroy_on_socks5conn_write_completed(tunnel);
    socks5tunnel_decref(tunnel);
}

/* Maybe we can make a separate rule set module */
static void socks5tunnel_on_socks5conn_request(struct socks5tunnel *tunnel,
        const struct s5_request *req)
{
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld socks5tunnel_on_socks5conn_request", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_REQUEST_PROCESS);

    struct s5_reply res;
    res.version = SOCKS_V5;
    res.rsv = 0;

    uint8_t cmd = req->cmd;
    if ((cmd != SOCKS5_CMD_CONNECT && cmd != SOCKS5_CMD_BIND && cmd != SOCKS5_CMD_UDP_ASSOCIATE)
            || req->version != SOCKS_V5 || req->rsv != 0) {
        if (cmd != SOCKS5_CMD_CONNECT && cmd != SOCKS5_CMD_BIND && cmd != SOCKS5_CMD_UDP_ASSOCIATE)
            res.reply = SOCKS5_REP_COMMAND_NOT_SUPPORTED;
        else
            res.reply = SOCKS5_REP_GENERAL_FAILURE;
        goto FAIL;
    }

    tunnel->socks5cmd = req->cmd;
    if (req->cmd == SOCKS5_CMD_CONNECT) { /* CONNECT */
        assert(tunnel->proxy == NULL);
        struct event_base *evbase = socks5server_get_event_base(tunnel->serv);
        struct evdns_base *dns_base = socks5server_get_dns_base(tunnel->serv);
        tunnel->proxy = dummy_proxy_new(tunnel, tunnel->id, evbase, dns_base);
        if (tunnel->proxy == NULL) {
            error("tunnel#%ld dummy_proxy_new() failed: %s (errno=%d)",
                    tunnel->id, strerror(errno), errno);
            res.reply = SOCKS5_REP_GENERAL_FAILURE;
            goto FAIL;
        }

        /* set callbacks for proxy */
        proxy_set_connection_success_cb(tunnel->proxy, socks5tunnel_on_proxy_connection_success);
        proxy_set_connection_error_cb(tunnel->proxy, socks5tunnel_on_proxy_connection_error);
        proxy_set_data_received_cb(tunnel->proxy, socks5tunnel_on_proxy_data_received);
        proxy_set_data_write_completed_cb(tunnel->proxy, socks5tunnel_on_proxy_data_write_completed);
        proxy_set_eof_cb(tunnel->proxy, socks5tunnel_on_proxy_eof);
        proxy_set_read_error_cb(tunnel->proxy, socks5tunnel_on_proxy_read_error);
        proxy_set_write_error_cb(tunnel->proxy, socks5tunnel_on_proxy_write_error);
        proxy_connect(tunnel->proxy, req->addr_type, &req->dest_addr, req->dest_port);
    } else if (req->cmd == SOCKS5_CMD_BIND) { /* BIND */
        assert(tunnel->bind_processor == NULL);
        struct event_base *evbase = socks5server_get_event_base(tunnel->serv);
        tunnel->bind_processor = s5bind_processor_new(evbase, tunnel, tunnel->id);
        if (tunnel->bind_processor == NULL) {
            error("tunnel#%ld s5bind_processor_new() failed: %s (errno=%d)",
                    tunnel->id, strerror(errno), errno);
            res.reply = SOCKS5_REP_GENERAL_FAILURE;
            goto FAIL;
        }
        struct s5bind_processor *processor = tunnel->bind_processor;
        s5bind_processor_set_on_bind_success_cb(processor, socks5tunnel_on_s5bind_processor_bind_success);
        s5bind_processor_set_on_bind_error_cb(processor, socks5tunnel_on_s5bind_processor_bind_error_cb);
        s5bind_processor_set_on_connection_success_cb(processor, socks5tunnel_on_s5bind_processor_connection_success_cb);
        s5bind_processor_set_on_connection_error_cb(processor, socks5tunnel_on_s5bind_processor_connection_error_cb);
        s5bind_processor_set_on_data_received_cb(processor, socks5tunnel_on_s5bind_processor_data_received_cb);
        s5bind_processor_set_on_data_write_completed_cb(processor, socks5tunnel_on_s5bind_processor_data_write_completed_cb);
        s5bind_processor_set_on_eof_cb(processor, socks5tunnel_on_s5bind_processor_eof_cb);
        s5bind_processor_set_on_read_error_cb(processor, socks5tunnel_on_s5bind_processor_read_error_cb);
        s5bind_processor_set_on_write_error_cb(processor, socks5tunnel_on_s5bind_processor_write_error_cb);
        s5bind_processor_start(tunnel->bind_processor);
    } else { /* UDP ASSOCIATE */
        assert(tunnel->udp_processor == NULL);
        /* create udp processor here */
        struct event_base *evbase = socks5server_get_event_base(tunnel->serv);
        struct evdns_base *dns_base = socks5server_get_dns_base(tunnel->serv);
        struct sockaddr_storage ss;
        socklen_t addrlen = sizeof(ss);
        if (socks5conn_getpeername(tunnel->socks5conn, (struct sockaddr *)&ss, &addrlen) == -1) {
            error("tunnel#%ld socks5conn_getpeername() failed: %s (errno=%d)",
                    tunnel->id, strerror(errno), errno);
            res.reply = SOCKS5_REP_GENERAL_FAILURE;
            goto FAIL;
        }

        tunnel->udp_processor = s5udp_associate_processor_new(evbase, dns_base, tunnel, tunnel->id,
                (struct sockaddr *)&ss, addrlen);
        if (tunnel->udp_processor == NULL) {
            error("tunnel#%ld s5udp_associate_processor_new() failed: %s (errno=%d)",
                    tunnel->id, strerror(errno), errno);
            res.reply = SOCKS5_REP_GENERAL_FAILURE;
            goto FAIL;
        }

        s5udp_associate_processor_start(tunnel->udp_processor,
                socks5tunnel_on_s5udp_associate_processor_success_cb,
                socks5tunnel_on_s5udp_associate_processor_error_cb);
    }
    socks5tunnel_decref(tunnel);
    return;

FAIL:
    assert(res.reply != SOCKS5_REP_SUCCEEDED);
    socks5conn_stop_read(tunnel->socks5conn);
    int n = socks5conn_write_s5_reply(tunnel->socks5conn, &res);
    if (n == YM_SUCCESS)
        socks5tunnel_destroy_on_socks5conn_write_completed(tunnel);
    else {
        error("tunnel#%ld socks5conn_write_s5_reply() failed: %s (errno=%d)", tunnel->id, strerror(errno), errno);
        socks5tunnel_free(tunnel);
    }
    socks5tunnel_decref(tunnel);
}


static void socks5tunnel_on_socks5conn_data(struct socks5tunnel *tunnel, struct evbuffer *buffer)
{
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld socks5tunnel_on_socks5conn_data", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_PROXY);
    assert(tunnel->socks5cmd == SOCKS5_CMD_CONNECT || tunnel->socks5cmd == SOCKS5_CMD_BIND);

    if (tunnel->socks5cmd == SOCKS5_CMD_CONNECT) {
        assert(tunnel->proxy != NULL);
        if (proxy_write(tunnel->proxy, buffer) == -1) {
            error("tunnel#%ld proxy_write() failed: %s (errno=%d)", tunnel->id, strerror(errno), errno);
            socks5tunnel_free(tunnel);
        }
    } else { /* SOCKS5_CMD_BIND */
        assert(tunnel->bind_processor != NULL);
        if (s5bind_processor_write(tunnel->bind_processor, buffer) == -1) {
            error("tunnel#%ld s5bind_processor_write() failed: %s (errno=%d)", tunnel->id, strerror(errno), errno);
            socks5tunnel_free(tunnel);
        }
    }
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_proxy_connection_success(struct socks5tunnel *tunnel,
        const struct sockaddr *addr, socklen_t addrlen)
{
    (void)addrlen;
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld socks5tunnel_on_proxy_connection_success", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_REQUEST_PROCESS);
    assert(tunnel->socks5cmd == SOCKS5_CMD_CONNECT);

    struct s5_reply res;
    s5_reply_init(&res, SOCKS5_REP_SUCCEEDED, addr);
    int n = socks5conn_write_s5_reply(tunnel->socks5conn, &res);
    if (n == YM_SUCCESS) {
        debug("now go to next stage: SOCKS5_STAGE_PROXY");
        socks5conn_set_stage(tunnel->socks5conn, SOCKS5_STAGE_PROXY);
        socks5conn_set_on_data_cb(tunnel->socks5conn, socks5tunnel_on_socks5conn_data);
    } else {
        error("socks5conn_write_s5_reply() failed: %s (errno=%d)", strerror(errno), errno);
        socks5tunnel_free(tunnel);
    }
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_proxy_connection_error(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    error("tunnel#%ld socks5tunnel_on_proxy_connection_error", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_REQUEST_PROCESS);
    assert(tunnel->socks5cmd == SOCKS5_CMD_CONNECT);

    struct s5_reply res;
    res.version = SOCKS_V5;
    res.rsv = 0;
    res.reply = SOCKS5_REP_GENERAL_FAILURE;

    int n = socks5conn_write_s5_reply(tunnel->socks5conn, &res);
    if (n == YM_SUCCESS) {
        socks5tunnel_destroy_on_socks5conn_write_completed(tunnel);
    } else {
        error("tunnel#%ld socks5conn_write_s5_reply() failed: %s (errno=%d)", tunnel->id, strerror(errno), errno);
        socks5tunnel_free(tunnel);
    }
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_proxy_data_received(struct socks5tunnel *tunnel, struct evbuffer *buffer)
{
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld socks5tunnel_on_proxy_data_received", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_PROXY);
    assert(tunnel->socks5cmd == SOCKS5_CMD_CONNECT);

    int n = socks5conn_write_data(tunnel->socks5conn, buffer);
    if (n == YM_ERROR) {
        error("tunnel#%ld socks5conn_write_data() failed: %s (errno=%d)", tunnel->id, strerror(errno), errno);
        socks5tunnel_free(tunnel);
    }
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_proxy_eof(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld socks5tunnel_on_proxy_eof", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_PROXY);
    assert(tunnel->socks5cmd == SOCKS5_CMD_CONNECT);

    tunnel->proxy_eof = 1;
    if (tunnel->socks5conn_eof)
        socks5tunnel_free(tunnel);
    else {
        socks5conn_shutdown_write(tunnel->socks5conn);
    }
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_proxy_read_error(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    error("tunnel#%ld socks5tunnel_on_proxy_read_error", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_PROXY);
    assert(tunnel->socks5cmd == SOCKS5_CMD_CONNECT);
    socks5tunnel_free(tunnel);
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_proxy_write_error(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    error("tunnel#%ld socks5tunnel_on_proxy_write_error", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_PROXY);
    assert(tunnel->socks5cmd == SOCKS5_CMD_CONNECT);
    socks5tunnel_free(tunnel);
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_proxy_data_write_completed(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_PROXY);
    assert(tunnel->socks5cmd == SOCKS5_CMD_CONNECT);
    debug("tunnel#%ld socks5tunnel_on_proxy_data_write_completed", tunnel->id);
    socks5tunnel_decref(tunnel);
}



/* for socks5 CMD=BIND processor */
static void socks5tunnel_on_s5bind_processor_bind_success(struct socks5tunnel *tunnel,
        const struct sockaddr *addr, socklen_t addrlen)
{
    (void)addrlen;
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld socks5tunnel_on_s5bind_processor_bind_success", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_REQUEST_PROCESS);
    assert(tunnel->socks5cmd == SOCKS5_CMD_BIND);

    /* the 1st reply */
    struct s5_reply res;
    s5_reply_init(&res, SOCKS5_REP_SUCCEEDED, addr);
    int n = socks5conn_write_s5_reply(tunnel->socks5conn, &res);
    if(n == YM_ERROR) {
        error("tunnel#%ld socks5conn_write_s5_reply() failed: %s (errno=%d)",
                tunnel->id, strerror(errno), errno);
        socks5tunnel_free(tunnel);
    }
    socks5tunnel_decref(tunnel);
}


static void socks5tunnel_on_s5bind_processor_bind_error_cb(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    error("tunnel#%ld socks5tunnel_on_s5bind_processor_bind_error_cb", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_REQUEST_PROCESS);
    assert(tunnel->socks5cmd == SOCKS5_CMD_BIND);

    struct s5_reply res;
    res.version = SOCKS_V5;
    res.rsv = 0;
    res.reply = SOCKS5_REP_GENERAL_FAILURE;

    int n = socks5conn_write_s5_reply(tunnel->socks5conn, &res);
    if (n == YM_SUCCESS) {
        socks5tunnel_destroy_on_socks5conn_write_completed(tunnel);
    } else {
        error("tunnel#%ld socks5conn_write_s5_reply() failed: %s (errno=%d)", tunnel->id, strerror(errno), errno);
        socks5tunnel_free(tunnel);
    }
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_s5bind_processor_connection_success_cb(struct socks5tunnel *tunnel,
        const struct sockaddr *addr, socklen_t addrlen)
{
    (void)addrlen;
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld socks5tunnel_on_s5bind_processor_connection_success_cb", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_REQUEST_PROCESS);
    assert(tunnel->socks5cmd == SOCKS5_CMD_BIND);

    /* the 2nd reply */
    struct s5_reply res;
    s5_reply_init(&res, SOCKS5_REP_SUCCEEDED, addr);
    int n = socks5conn_write_s5_reply(tunnel->socks5conn, &res);
    if (n == YM_SUCCESS) {
        debug("now go to next stage: SOCKS5_STAGE_PROXY");
        socks5conn_set_stage(tunnel->socks5conn, SOCKS5_STAGE_PROXY);
        socks5conn_set_on_data_cb(tunnel->socks5conn, socks5tunnel_on_socks5conn_data);
    } else {
        error("socks5conn_write_s5_reply() failed: %s (errno=%d)", strerror(errno), errno);
        socks5tunnel_free(tunnel);
    }
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_s5bind_processor_connection_error_cb(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    error("tunnel#%ld socks5tunnel_on_s5bind_processor_connection_error_cb", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_REQUEST_PROCESS);
    assert(tunnel->socks5cmd == SOCKS5_CMD_BIND);

    struct s5_reply res;
    res.version = SOCKS_V5;
    res.rsv = 0;
    res.reply = SOCKS5_REP_GENERAL_FAILURE;

    int n = socks5conn_write_s5_reply(tunnel->socks5conn, &res);
    if (n == YM_SUCCESS) {
        socks5tunnel_destroy_on_socks5conn_write_completed(tunnel);
    } else {
        error("tunnel#%ld socks5conn_write_s5_reply() failed: %s (errno=%d)", tunnel->id, strerror(errno), errno);
        socks5tunnel_free(tunnel);
    }
    socks5tunnel_decref(tunnel);
}


static void socks5tunnel_on_s5bind_processor_data_received_cb(struct socks5tunnel *tunnel,
        struct evbuffer *buffer)
{
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld socks5tunnel_on_s5bind_processor_data_received_cb", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_PROXY);
    assert(tunnel->socks5cmd == SOCKS5_CMD_BIND);

    int n = socks5conn_write_data(tunnel->socks5conn, buffer);
    if (n == YM_ERROR) {
        error("tunnel#%ld socks5conn_write_data() failed: %s (errno=%d)", tunnel->id, strerror(errno), errno);
        socks5tunnel_free(tunnel);
    }
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_s5bind_processor_data_write_completed_cb(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_PROXY);
    assert(tunnel->socks5cmd == SOCKS5_CMD_BIND);
    debug("tunnel#%ld socks5tunnel_on_s5bind_processor_data_write_completed_cb", tunnel->id);
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_s5bind_processor_eof_cb(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld socks5tunnel_on_s5bind_processor_eof_cb. we now close the tunnel.", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_PROXY);
    assert(tunnel->socks5cmd == SOCKS5_CMD_BIND);

    tunnel->bind_processor_eof = 1;
    if (tunnel->socks5conn_eof)
        socks5tunnel_free(tunnel);
    else {
        socks5conn_shutdown_write(tunnel->socks5conn);
    }
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_s5bind_processor_read_error_cb(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    error("tunnel#%ld socks5tunnel_on_s5bind_processor_read_error_cb", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_PROXY);
    assert(tunnel->socks5cmd == SOCKS5_CMD_BIND);
    socks5tunnel_free(tunnel);
    socks5tunnel_decref(tunnel);
}

static void socks5tunnel_on_s5bind_processor_write_error_cb(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    error("tunnel#%ld socks5tunnel_on_s5bind_processor_write_error_cb", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_PROXY);
    assert(tunnel->socks5cmd == SOCKS5_CMD_BIND);
    socks5tunnel_free(tunnel);
    socks5tunnel_decref(tunnel);
}


static void socks5tunnel_on_s5udp_associate_processor_success_cb(struct socks5tunnel *tunnel,
        const struct sockaddr *addr, socklen_t addrlen)
{
    (void)addrlen;
    socks5tunnel_incref(tunnel);
    debug("tunnel#%ld socks5tunnel_on_s5udp_associate_processor_success_cb", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_REQUEST_PROCESS);
    assert(tunnel->socks5cmd == SOCKS5_CMD_UDP_ASSOCIATE);

    struct s5_reply res;
    s5_reply_init(&res, SOCKS5_REP_SUCCEEDED, addr);
    int n = socks5conn_write_s5_reply(tunnel->socks5conn, &res);
    if (n == YM_SUCCESS) {
        debug("now go to next stage: SOCKS5_STAGE_PROXY");
        socks5conn_set_stage(tunnel->socks5conn, SOCKS5_STAGE_PROXY);
    } else {
        error("socks5conn_write_s5_reply() failed: %s (errno=%d)", strerror(errno), errno);
        socks5tunnel_free(tunnel);
    }
    socks5tunnel_decref(tunnel);
}


static void socks5tunnel_on_s5udp_associate_processor_error_cb(struct socks5tunnel *tunnel)
{
    socks5tunnel_incref(tunnel);
    error("tunnel#%ld socks5tunnel_on_s5udp_associate_processor_error_cb", tunnel->id);
    assert(socks5conn_get_stage(tunnel->socks5conn) == SOCKS5_STAGE_REQUEST_PROCESS);
    assert(tunnel->socks5cmd == SOCKS5_CMD_UDP_ASSOCIATE);

    struct s5_reply res;
    res.version = SOCKS_V5;
    res.rsv = 0;
    res.reply = SOCKS5_REP_GENERAL_FAILURE;

    int n = socks5conn_write_s5_reply(tunnel->socks5conn, &res);
    if (n == YM_SUCCESS) {
        socks5tunnel_destroy_on_socks5conn_write_completed(tunnel);
    } else {
        error("tunnel#%ld socks5conn_write_s5_reply() failed: %s (errno=%d)",
                tunnel->id, strerror(errno), errno);
        socks5tunnel_free(tunnel);
    }
    socks5tunnel_decref(tunnel);
}
