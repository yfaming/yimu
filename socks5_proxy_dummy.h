#ifndef SOCKS5_PROXY_DUMMY_H
#define SOCKS5_PROXY_DUMMY_H
#include <event2/event.h>
#include <event2/dns.h>

#include "logging.h"
#include "socks5_proxy.h"

struct socks5tunnel;

/* a proxy that does no "proxy" */
struct proxy *dummy_proxy_new(struct socks5tunnel *tunnel, long tunnel_id,
        struct event_base *evbase, struct evdns_base *dns_base);

#endif /* ifndef SOCKS5_PROXY_DUMMY_H */
