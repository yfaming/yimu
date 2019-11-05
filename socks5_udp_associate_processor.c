#define _ISOC99_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <event2/dns.h>
#include <event2/util.h>

#include "logging.h"
#include "socks5_udp_associate_processor.h"
#include "socks5_protocol.h"
#include "util.h"

static void socks5udp_associate_processor_incref(struct s5udp_associate_processor *processor);
static void socks5udp_associate_processor_decref(struct s5udp_associate_processor *processor);
static void socks5udp_associate_processor_real_free(struct s5udp_associate_processor *processor);

struct s5udp_associate_processor {
    struct event *udp_event;
    struct event_base *evbase;
    struct evdns_base *dns_base;
    struct socks5tunnel *tunnel;
    long tunnel_id;

    struct sockaddr *client_addr;
    socklen_t addrlen;

    int refcnt;
};

struct s5udp_associate_processor *s5udp_associate_processor_new(struct event_base *evbase,
        struct evdns_base *dns_base, struct socks5tunnel *tunnel, long tunnel_id,
        const struct sockaddr *client_address, socklen_t addrlen)
{
    struct sockaddr *client_addr = NULL;
    struct s5udp_associate_processor *processor = NULL;

    client_addr = malloc(addrlen);
    if (client_addr == NULL) {
        error("tunnel#%ld malloc() for client_addr failed: %s (errno=%d)", tunnel_id, strerror(errno), errno);
        goto FAIL;
    }
    memcpy(client_addr, client_address, addrlen);

    processor = malloc(sizeof(*processor));
    if (processor == NULL) {
        error("tunnel#%ld malloc() for struct s5udp_associate_processor failed: %s (errno=%d)",
                tunnel_id, strerror(errno), errno);
        goto FAIL;
    }

    processor->udp_event = NULL;
    processor->evbase = evbase;
    processor->dns_base = dns_base;
    processor->tunnel = tunnel;
    processor->tunnel_id = tunnel_id;

    processor->client_addr = client_addr;
    processor->addrlen = addrlen;
    processor->refcnt = 1;
    return processor;

FAIL:
    if (processor)
        free(processor);
    if (client_addr)
        free(client_addr);
    return NULL;
}


void s5udp_associate_processor_free(struct s5udp_associate_processor *processor)
{
    socks5udp_associate_processor_decref(processor);
}


static void socks5udp_associate_processor_incref(struct s5udp_associate_processor *processor)
{
    processor->refcnt++;
}

static void socks5udp_associate_processor_decref(struct s5udp_associate_processor *processor)
{
    processor->refcnt--;
    if (processor->refcnt == 0)
        socks5udp_associate_processor_real_free(processor);
}

static void socks5udp_associate_processor_real_free(struct s5udp_associate_processor *processor)
{
    if (processor->udp_event) {
        int fd = event_get_fd(processor->udp_event);
        if (fd >= 0)
            close(fd);
        event_free(processor->udp_event);
    }
    free(processor->client_addr);
    free(processor);
}


/* the udp relay server logic */
static void _udp_cb(int servfd, short event, void *user_arg);

void s5udp_associate_processor_start(struct s5udp_associate_processor *processor,
        s5udp_associate_processor_on_success_cb on_success_cb,
        s5udp_associate_processor_on_error_cb on_error_cb)
{
    socks5udp_associate_processor_incref(processor);
    int fd = -1;
    fd = socket(processor->client_addr->sa_family, SOCK_DGRAM, 0);
    if (fd == -1) {
        error("tunnel#%ld socket() failed: %s (errno=%d)", processor->tunnel_id, strerror(errno), errno);
        goto FAIL;
    }
    if (evutil_make_socket_nonblocking(fd) == -1) {
        error("tunnel#%ld evutil_make_socket_nonblocking() failed: %s (errno=%d)",
                processor->tunnel_id, strerror(errno), errno);
        goto FAIL;
    }

    struct sockaddr_storage ss;
    socklen_t addrlen = 0;
    memset(&ss, 0, sizeof(ss));
    ss.ss_family = processor->client_addr->sa_family;
    assert(ss.ss_family == AF_INET || ss.ss_family == AF_INET6);
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *addrv4 = (struct sockaddr_in *)&ss;
        addrv4->sin_addr.s_addr = INADDR_ANY;
        addrv4->sin_port = htons(0);
        addrlen = sizeof(*addrv4);
    } else {
        struct sockaddr_in6 *addrv6 = (struct sockaddr_in6 *)&ss;
        addrv6->sin6_addr = in6addr_any;
        addrv6->sin6_port = htons(0);
        addrlen = sizeof(*addrv6);
    }

    if (bind(fd, (struct sockaddr *)&ss, addrlen) == -1) {
        error("tunnel#%ld bind() failed: %s (errno=%d)",
                processor->tunnel_id, strerror(errno), errno);
        goto FAIL;
    }

    processor->udp_event = event_new(processor->evbase, fd, EV_READ|EV_PERSIST, _udp_cb, processor);
    if (processor->udp_event == NULL) {
        error("tunnel#%ld socket() failed: %s (errno=%d)",
                processor->tunnel_id, strerror(errno), errno);
        goto FAIL;
    }

    if (event_add(processor->udp_event, NULL) == -1) {
        error("tunnel#%ld event_add() failed: %s (errno=%d)",
                processor->tunnel_id, strerror(errno), errno);
        goto FAIL;
    }

    if (on_success_cb)
        on_success_cb(processor->tunnel, (struct sockaddr *)&ss, addrlen);
    socks5udp_associate_processor_decref(processor);
    return;

FAIL:
    if (processor->udp_event) {
        event_free(processor->udp_event);
        processor->udp_event = NULL;
    }
    if (fd >= 0)
        close(fd);
    if (on_error_cb)
        on_error_cb(processor->tunnel);
    socks5udp_associate_processor_decref(processor);
}


static void s5udp_associate_processor_sendto_client(struct s5udp_associate_processor *processor,
        const struct sockaddr *from_addr, socklen_t addrlen, const char *data, size_t len);
static void s5udp_associate_processor_sendto_remote(struct s5udp_associate_processor *processor,
        const struct s5_udp_request *req);

static void sendto_host(struct s5udp_associate_processor *processor, const char *domain, uint16_t port,
        const char *data, size_t len);
void getaddrinfo_cb(int result, struct evutil_addrinfo *res, void *arg);

static void _udp_cb(int servfd, short event, void *user_arg)
{
    (void)event;
    struct s5udp_associate_processor *processor = user_arg;
    struct sockaddr_storage ss;
    socklen_t addrlen = sizeof(ss);

    ssize_t n = 0;
    char buf[10240];
    while (1) {
        addrlen = sizeof(ss);
        n = recvfrom(servfd, buf, sizeof(buf), MSG_TRUNC, (struct sockaddr *)&ss, &addrlen);
        if (n == -1) {
            if (errno == EAGAIN)
                break;
            else {
                error("tunnel#%ld recvfrom() failed: %s (errno=%d)",
                        processor->tunnel_id, strerror(errno), errno);
                continue;
            }
        }

        if ((size_t)n > sizeof(buf)) {
            warn("tunnel#%ld received udp data truncated", processor->tunnel_id);
            continue;
        }

        if (sockaddr_cmp((struct sockaddr *)&ss, processor->client_addr) == 0) {
            /* got data from client, send it to remote */
            struct s5_udp_request req;
            if (read_s5_udp_request(buf, n, &req) != YM_SUCCESS) {
                error("tunnel#%ld read_s5_udp_request() failed: %s (errno=%d)",
                        processor->tunnel_id, strerror(errno), errno);
                /* nothing else to do */
            } else {
                s5udp_associate_processor_sendto_remote(processor, &req);
            }
        } else {
            /* got data from remote, send it to client */
            s5udp_associate_processor_sendto_client(processor,(struct sockaddr *)&ss, addrlen, buf, n);
        }
    }
}


/* encapusulate into s5_udp_request and send to client */
static void s5udp_associate_processor_sendto_client(struct s5udp_associate_processor *processor,
        const struct sockaddr *from_addr, socklen_t addrlen, const char *data, size_t len)
{
    (void)addrlen;
    assert(from_addr->sa_family == AF_INET || from_addr->sa_family == AF_INET6);

    char *buf = NULL;
    /* IPv4: rsv(2) + frag(1) + atyp(1) + dst.addr(4) + dst.port(2)  = 10
     * IPv6: rsv(2) + frag(1) + atyp(1) + dst.addr(16) + dst.port(2) = 22
     */
    size_t headerlen = from_addr->sa_family == AF_INET ? 10 : 22;
    buf = malloc(headerlen + len);
    if (buf == NULL) {
        error("tunnel#%ld malloc() failed: %s (errno=%d)",
                processor->tunnel_id, strerror(errno), errno);
        goto FAIL;
    }

    /* add s5_udp_request header */
    char *ptr = buf;
    *(uint16_t *)ptr = 0; /* rsv */
    ptr += 2;
    *ptr = 0; /* frag. We do not support fragmentat. */
    ptr++;
    if (from_addr->sa_family == AF_INET) {
        *ptr = SOCKS5_ATYPE_IPV4;
        ptr++;
        struct sockaddr_in *in = (struct sockaddr_in *)from_addr;
        memcpy(ptr, &in->sin_addr, sizeof(struct in_addr));
        ptr += 4;
        *(int16_t *)ptr = in->sin_port;
        ptr += 2;
    } else {
        *ptr = SOCKS5_ATYPE_IPV6;
        ptr++;
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)from_addr;
        memcpy(ptr, &in6->sin6_addr, sizeof(struct in6_addr));
        ptr += 16;
        *(int16_t *)ptr = in6->sin6_port;
        ptr += 2;
    }
    assert(ptr - buf == headerlen);

    /* add data */
    memcpy(ptr, data, len);

    int udpfd = event_get_fd(processor->udp_event);
    if (sendto(udpfd, buf, headerlen + len, 0, processor->client_addr, processor->addrlen) == -1) {
        error("tunnel#%ld sendto() failed: %s (errno=%d)",
                processor->tunnel_id, strerror(errno), errno);
        goto FAIL;
    }

    free(buf);
    return;

FAIL:
    if (buf)
        free(buf);
    return;
}


static void s5udp_associate_processor_sendto_remote(struct s5udp_associate_processor *processor, const struct s5_udp_request *req)
{
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t addrlen = 0;

    if (req->rsv != 0) {
        error("tunnel#%ld s5_udp_request.rsv should be 0", processor->tunnel_id);
        return;
    }
    if (req->frag != 0) {
        error("tunnel#%ld we do not support frament of struct s5_udp_request", processor->tunnel_id);
        return;
    }

    if (req->addr_type == SOCKS5_ATYPE_IPV4 || req->addr_type == SOCKS5_ATYPE_IPV6) {
        if (req->addr_type == SOCKS5_ATYPE_IPV4) {
            addrlen = sizeof(struct sockaddr_in);
            struct sockaddr_in *in = (struct sockaddr_in *)&ss;
            in->sin_family = AF_INET;
            memcpy(&in->sin_addr, &req->dest_addr.ipv4, sizeof(struct in_addr));
            in->sin_port = htons(req->dest_port);
        } else if (req->addr_type == SOCKS5_ATYPE_IPV6) {
            addrlen = sizeof(struct sockaddr_in6);
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;
            in6->sin6_family = AF_INET6;
            memcpy(&in6->sin6_addr, &req->dest_addr.ipv6, sizeof(struct in6_addr));
            in6->sin6_port = htons(req->dest_port);
        }

        int udpfd = event_get_fd(processor->udp_event);
        if (sendto(udpfd, req->data, req->datalen, 0, (struct sockaddr *)&ss, addrlen) == -1) {
            error("tunnel#%ld sendto() failed: %s (errno=%d)",
                    processor->tunnel_id, strerror(errno), errno);
        }
        return;
    } else { /* SOCKS5_ATYPE_DOMAINNAME */
        sendto_host(processor, req->dest_addr.domain, req->dest_port, req->data, req->datalen);
    }
}

struct user_arg {
    char *data;
    size_t len;
    int udpfd;
    long tunnel_id;
};

static void sendto_host(struct s5udp_associate_processor *processor, const char *domain, uint16_t port,
        const char *data, size_t len)
{
        char port_str[8]; /* more than enough */
        snprintf(port_str, sizeof(port_str), "%d", port);

        struct evutil_addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = EVUTIL_AI_NUMERICSERV | EVUTIL_AI_ADDRCONFIG;
        hints.ai_family = processor->client_addr->sa_family;
        hints.ai_socktype = SOCK_DGRAM;

        struct user_arg *arg = malloc(sizeof(struct user_arg));
        if (arg == NULL) {
            error("tunnel#%ld malloc() for struct arg failed: %s (errno=%d)",
                    processor->tunnel_id, strerror(errno), errno);
            return;
        }

        arg->data = malloc(len);
        if (arg->data == NULL) {
            error("tunnel#%ld malloc() failed: %s (errno=%d)", processor->tunnel_id, strerror(errno), errno);
            free(arg);
            return;
        }
        memcpy(arg->data, data, len);
        arg->len = len;
        arg->tunnel_id = processor->tunnel_id;
        arg->udpfd = event_get_fd(processor->udp_event);
        evdns_getaddrinfo(processor->dns_base, domain, port_str, &hints, getaddrinfo_cb, arg);
}

void getaddrinfo_cb(int result, struct evutil_addrinfo *res, void *arg)
{
    struct user_arg *user_arg = arg;
    if (result != 0) {
        error("tunnel#%ld evdns_getaddrinfo() failed: %s", evutil_gai_strerror(result));
        return;
    }

    if (sendto(user_arg->udpfd, user_arg->data, user_arg->len, 0, res->ai_addr, res->ai_addrlen) == -1) {
        error("tunnel#%ld sendto() failed: %s (errno=%d)",
                user_arg->tunnel_id, strerror(errno), errno);
    }
}
