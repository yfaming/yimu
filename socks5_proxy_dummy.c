#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "logging.h"
#include "socks5_proxy_dummy.h"
#include "util.h"


struct dummy_imp {
    struct bufferevent *bev;
    struct evdns_base *dns_base;
    int connected;
    int write_is_shutdown;

    long tunnel_id;
    struct socks5tunnel *tunnel;
    struct proxy *proxy;

    on_connection_succeess_cb connection_succeess_cb;
    on_connection_error_cb connection_error_cb;
    on_data_received_cb data_received_cb;
    on_data_write_completed_cb data_write_completed_cb;
    on_eof_cb eof_cb;
    on_read_error_cb read_error_cb;
    on_write_error_cb write_error_cb;
};

static struct dummy_imp *dummy_imp_new(struct socks5tunnel *tunnel, long tunnel_id,
        struct event_base *evbase, struct evdns_base *dns_base);
static void dummy_imp_free(void *imp);

static void dummy_imp_set_connection_success_cb(struct proxy *proxy, on_connection_succeess_cb cb);
static void dummy_imp_set_connection_error_cb(struct proxy *proxy, on_connection_error_cb cb);
static void dummy_imp_set_data_received_cb(struct proxy *proxy, on_data_received_cb cb);
static void dummy_imp_set_data_write_completed_cb(struct proxy *proxy, on_data_write_completed_cb cb);
static void dummy_imp_set_eof_cb(struct proxy *proxy, on_eof_cb cb);
static void dummy_imp_set_read_error_cb(struct proxy *proxy, on_read_error_cb cb);
static void dummy_imp_set_write_error_cb(struct proxy *proxy, on_write_error_cb cb);

static void dummy_imp_shutdown_write(struct proxy *proxy); /* like shutdown(2) */
static void dummy_imp_connect(struct proxy *proxy, uint8_t addr_type, const union socks5_address *dest_addr, uint16_t dest_port);
static int dummy_imp_write(struct proxy *proxy, struct evbuffer *buffer);


struct proxy *dummy_proxy_new(struct socks5tunnel *tunnel, long tunnel_id,
        struct event_base *evbase, struct evdns_base *dns_base)
{
    struct dummy_imp *imp = NULL;
    struct proxy *proxy = NULL;
    imp = dummy_imp_new(tunnel, tunnel_id, evbase, dns_base);
    if (imp == NULL) {
        error("dummy_imp_new() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }

    static struct proxy_ops ops = {
        dummy_imp_set_connection_success_cb,
        dummy_imp_set_connection_error_cb,
        dummy_imp_set_data_received_cb,
        dummy_imp_set_data_write_completed_cb,
        dummy_imp_set_eof_cb,
        dummy_imp_set_read_error_cb,
        dummy_imp_set_write_error_cb,
        dummy_imp_free,
        dummy_imp_shutdown_write,
        dummy_imp_connect,
        dummy_imp_write,
    };

    proxy = proxy_new(ops, imp);
    if (proxy == NULL) {
        error("proxy_new() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }
    imp->proxy = proxy;
    return proxy;

FAIL:
    if (proxy)
        free(proxy);
    if (imp)
        dummy_imp_free(imp);
    return NULL;
}

/* *********** 以下皆是实现而已 *************** */
static void _readcb(struct bufferevent *bev, void *user_arg);
static void _writecb(struct bufferevent *bev, void *user_arg);
static void _eventcb(struct bufferevent *bev, short event, void *user_arg);

static struct dummy_imp *dummy_imp_new(struct socks5tunnel *tunnel, long tunnel_id,
        struct event_base *evbase, struct evdns_base *dns_base)
{
    struct bufferevent *bev = NULL;
    struct dummy_imp *imp = NULL;

    bev = bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE);
    if (bev == NULL) {
        error("bufferevent_socket_new() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }

    imp = malloc(sizeof(struct dummy_imp));
    if (imp == NULL) {
        error("malloc() for authenticator failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }
    memset(imp, 0, sizeof(struct dummy_imp));
    imp->bev = bev;
    imp->dns_base = dns_base;
    imp->connected = 0;
    imp->write_is_shutdown = 0;
    imp->tunnel = tunnel;
    imp->tunnel_id = tunnel_id;
    imp->proxy = NULL;

    bufferevent_setcb(bev, _readcb, _writecb, _eventcb, imp);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    return imp;

FAIL:
    if (imp)
        free(imp);
    if (bev)
        bufferevent_free(bev);
    return NULL;
}


static void dummy_imp_free(void *imp)
{
    struct dummy_imp *real_imp = imp;
    debug("tunnel#%ld proxy dummy destroy", real_imp->tunnel_id);
    bufferevent_free(real_imp->bev);
    free(real_imp);
}

static void dummy_imp_set_connection_success_cb(struct proxy *proxy, on_connection_succeess_cb cb)
{
    struct dummy_imp *imp = proxy->imp;
    imp->connection_succeess_cb = cb;
}


static void dummy_imp_set_connection_error_cb(struct proxy *proxy, on_connection_error_cb cb)
{
    struct dummy_imp *imp = proxy->imp;
    imp->connection_error_cb = cb;
}

static void dummy_imp_set_data_received_cb(struct proxy *proxy, on_data_received_cb cb)
{
    struct dummy_imp *imp = proxy->imp;
    imp->data_received_cb = cb;
}

static void dummy_imp_set_data_write_completed_cb(struct proxy *proxy, on_data_write_completed_cb cb)
{
    struct dummy_imp *imp = proxy->imp;
    imp->data_write_completed_cb = cb;
}

static void dummy_imp_set_eof_cb(struct proxy *proxy, on_eof_cb cb)
{
    struct dummy_imp *imp = proxy->imp;
    imp->eof_cb = cb;
}

static void dummy_imp_set_read_error_cb(struct proxy *proxy, on_read_error_cb cb)
{
    struct dummy_imp *imp = proxy->imp;
    imp->read_error_cb = cb;
}

static void dummy_imp_set_write_error_cb(struct proxy *proxy, on_write_error_cb cb)
{
    struct dummy_imp *imp = proxy->imp;
    imp->write_error_cb = cb;
}

static void dummy_imp_shutdown_write(struct proxy *proxy) /* like shutdown(2) */
{
    struct dummy_imp *imp = proxy->imp;
    assert(imp->connected);
    debug("tunnel#%ld dummy_imp_shutdown_write", imp->tunnel_id);
    imp->write_is_shutdown = 1;
}

static void dummy_imp_connect(struct proxy *proxy, uint8_t addr_type, const union socks5_address *dest_addr, uint16_t dest_port)
{
    struct dummy_imp *imp = proxy->imp;
    debug("tunnel#%ld dummy_imp_connect", imp->tunnel_id);

    struct sockaddr_in sockaddrv4;
    struct sockaddr_in6 sockaddrv6;
    struct sockaddr *sockaddr = NULL;
    socklen_t addrlen = 0;
    if (addr_type == SOCKS5_ATYPE_IPV4 || addr_type == SOCKS5_ATYPE_IPV6) {
        if (addr_type == SOCKS5_ATYPE_IPV4) {
            memset(&sockaddrv4, 0, sizeof(sockaddrv4));
            sockaddrv4.sin_family = AF_INET;
            sockaddrv4.sin_addr = dest_addr->ipv4;
            sockaddrv4.sin_port = htons(dest_port);
            sockaddr = (struct sockaddr *)&sockaddrv4;
            addrlen = sizeof(sockaddrv4);
        } else { /* SOCKS5_ATYPE_IPV6 */
            memset(&sockaddrv6, 0, sizeof(sockaddrv6));
            sockaddrv6.sin6_family = AF_INET6;
            sockaddrv6.sin6_addr = dest_addr->ipv6;
            sockaddrv4.sin_port = htons(dest_port);
            sockaddr = (struct sockaddr *)&sockaddrv6;
            addrlen = sizeof(sockaddrv6);
        }
        bufferevent_socket_connect(imp->bev, sockaddr, addrlen);
    } else { /* SOCKS5_ATYPE_DOMAINNAME */
        bufferevent_socket_connect_hostname(imp->bev, imp->dns_base,
                AF_UNSPEC, dest_addr->domain, dest_port);
    }
}

static int dummy_imp_write(struct proxy *proxy, struct evbuffer *buffer)
{
    struct dummy_imp *imp = proxy->imp;
    debug("tunnel#%ld dummy_imp_write", imp->tunnel_id);
    assert(imp->write_is_shutdown == 0);
    return bufferevent_write_buffer(imp->bev, buffer);
}

static void _readcb(struct bufferevent *bev, void *user_arg)
{
    struct dummy_imp *imp = user_arg;
    proxy_incref(imp->proxy);
    debug("tunnel#%ld _readcb: data received", imp->tunnel_id);
    if (imp->data_received_cb)
        imp->data_received_cb(imp->tunnel, bufferevent_get_input(bev));
    proxy_decref(imp->proxy);
}

static void _writecb(struct bufferevent *bev, void *user_arg)
{
    (void)bev;
    struct dummy_imp *imp = user_arg;
    proxy_incref(imp->proxy);
    debug("tunnel#%ld _writecb: data write completed", imp->tunnel_id);
    if (imp->write_is_shutdown) {
        /* do real shutdown only when buffer is emptied */
        int n = shutdown(bufferevent_getfd(imp->bev), SHUT_WR);
        if (n == -1) {
            error("tunnel#%ld shutdown() failed: %s (errno=%d)",
                    imp->tunnel_id, strerror(errno), errno);
        }
    }

    if (imp->data_write_completed_cb) {
        imp->data_write_completed_cb(imp->tunnel);
    }
    proxy_decref(imp->proxy);
}

static void _eventcb(struct bufferevent *bev, short event, void *user_arg)
{
    struct dummy_imp *imp = user_arg;
    proxy_incref(imp->proxy);

    char eventstr[128];
    str_bufferevent_event(event, eventstr, sizeof(eventstr));
    debug("tunnel#%ld proxy dummy: event: %s", imp->tunnel_id, eventstr);

    if (event & BEV_EVENT_EOF) {
        info("tunnel#%ld proxy dummy: EOF encountered", imp->tunnel_id);
        if (imp->eof_cb)
            imp->eof_cb(imp->tunnel);
    }
    if (event & BEV_EVENT_ERROR) {
        if (!imp->connected) {
            error("tunnel#%ld proxy dummy: connection error", imp->tunnel_id);
            if (imp->connection_error_cb)
                imp->connection_error_cb(imp->tunnel);
        } else {
            if (event & BEV_EVENT_READING) {
                error("tunnel#%ld proxy dummy: read error", imp->tunnel_id);
                if (imp->read_error_cb)
                    imp->read_error_cb(imp->tunnel);
            } else {
                error("tunnel#%ld proxy dummy: write error", imp->tunnel_id);
                if (imp->write_error_cb)
                    imp->write_error_cb(imp->tunnel);
            }
        }
    }
    if (event & BEV_EVENT_CONNECTED) {
        debug("tunnel#%ld proxy dummy: connected", imp->tunnel_id);
        imp->connected = 1;

        struct sockaddr_storage sockaddr;
        socklen_t addrlen = sizeof(sockaddr);
        memset(&sockaddr, 0, sizeof(sockaddr));
        int n = getsockname(bufferevent_getfd(bev), (struct sockaddr *)&sockaddr, &addrlen);
        if (n == 0) {
            imp->connection_succeess_cb(imp->tunnel, (struct sockaddr *)&sockaddr, addrlen);
        } else {
            error("tunnel#%ld proxy dummy getsockname() failed: %s (errno=%d)",
                    imp->tunnel_id, strerror(errno), errno);
            if (imp->connection_error_cb)
                imp->connection_error_cb(imp->tunnel);
        }

    }
    /* no possible: BEV_EVENT_TIMEOUT*/

    proxy_decref(imp->proxy);
}
