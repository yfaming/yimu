#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/listener.h>

#include "logging.h"
#include "socks5_tunnel.h"
#include "util.h"

struct socks5server {
    struct evconnlistener *listener;
    struct sockaddr *listenaddr;
    socklen_t addrlen;

    int next_id;

    /* socks5server references, but does not own auth_manager */
    struct s5auth_manager *auth_manager;
    /* socks5server references, but does not own dns_base */
    struct evdns_base *dns_base;

    /* extra fd used to handle file descriptor exhaust */
    int extra_fd;
};

static void listener_cb(struct evconnlistener *listener, evutil_socket_t connfd,
        struct sockaddr *sa, int socklen, void *user_arg);
static void socks5server_on_new_connection(struct socks5server *serv, evutil_socket_t connfd,
        struct sockaddr *peeraddr, int addrlen);
static void error_cb(struct evconnlistener *listener, void *user_arg);

struct socks5server *socks5server_new(struct event_base *base,
        const struct sockaddr *servaddr, int addrlen,
        struct s5auth_manager *auth_manager, struct evdns_base *dns_base)
{
    struct evconnlistener *listener = NULL;
    struct sockaddr *listenaddr = NULL;
    int extra_fd = -1;
    struct socks5server *serv = NULL;

    listener = evconnlistener_new_bind(base, NULL/*callback*/, NULL/*user_args*/,
            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, 1024, servaddr, addrlen);
    if (listener == NULL) {
        error("evconnlistener_new_bind() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }

    listenaddr = malloc(addrlen);
    if (listenaddr == NULL) {
        error("malloc() for listenaddr failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }
    memcpy(listenaddr, servaddr, addrlen);

    extra_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (extra_fd == -1) {
        error("socket() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }

    serv = malloc(sizeof(struct socks5server));
    if (serv == NULL) {
        error("malloc() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }
    serv->listener = listener;
    serv->listenaddr = listenaddr;
    serv->addrlen = addrlen;

    serv->next_id = 0;

    assert(auth_manager != NULL);
    serv->auth_manager = auth_manager;
    assert(dns_base != NULL);
    serv->dns_base = dns_base;

    serv->extra_fd = extra_fd;

    evconnlistener_set_cb(listener, listener_cb, serv);
    evconnlistener_set_error_cb(listener, error_cb);

    char servaddr_str[SOCKADDR_STRLEN];
    sockaddr_ntop(servaddr, servaddr_str, sizeof(servaddr_str));
    info("listening on %s", servaddr_str);
    return serv;

FAIL:
    free(serv);
    if (extra_fd >= 0)
        close(extra_fd);
    free(listenaddr);
    if (listener)
        evconnlistener_free(listener);
    return NULL;
}

void socks5server_free(struct socks5server *serv)
{
    evconnlistener_free(serv->listener);
    free(serv->listenaddr);
    if (serv->extra_fd >= 0)
        close(serv->extra_fd);
    free(serv);
}

struct event_base *socks5server_get_event_base(struct socks5server *serv)
{
    return evconnlistener_get_base(serv->listener);
}

struct s5auth_manager *socks5server_get_auth_manager(struct socks5server *serv)
{
    return serv->auth_manager;
}

struct evdns_base *socks5server_get_dns_base(struct socks5server *serv)
{
    return serv->dns_base;
}

int socks5server_gen_id(struct socks5server *serv)
{
    return serv->next_id++;
}

static void listener_cb(struct evconnlistener *listener, evutil_socket_t connfd,
        struct sockaddr *peeraddr, int addrlen, void *user_arg)
{
    (void)listener;
    struct socks5server *serv = user_arg;
    socks5server_on_new_connection(serv, connfd, peeraddr, addrlen);
}

static void socks5server_on_new_connection(struct socks5server *serv, evutil_socket_t connfd,
        struct sockaddr *peeraddr, int addrlen)
{
    struct socks5tunnel *tunnel = socks5tunnel_new(serv, connfd, peeraddr, addrlen);
    if (tunnel == NULL) {
        error("socks5tunnel_new() failed: %s (errno=%d)", strerror(errno), errno);
        close(connfd);
        return;
    }
}

/* mitigate the "Too many open files" error */
static void error_cb(struct evconnlistener *listener, void *user_arg)
{
    (void)listener;
    error("socks5_server: %s", strerror(EVUTIL_SOCKET_ERROR()));

    if (EVUTIL_SOCKET_ERROR() != EMFILE)
        return;

    struct socks5server *serv = user_arg;
    assert(serv != NULL);
    if (serv->extra_fd >= 0) {
        close(serv->extra_fd);
        serv->extra_fd = -1;

        int i = 1;
        int fd = -1;
        while (i <= 100) {
            fd = accept(evconnlistener_get_fd(serv->listener), NULL, NULL);
            if (fd >= 0)
                close(fd);
            else
                break;

            i++;
        }
        error("socks5_server: killed %d new connections", i);

        serv->extra_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (serv->extra_fd == -1)
            error("socks5_server: oops, we have no extra fd any more...");
    }
}
