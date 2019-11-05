#ifndef SOCKS5_SERVER_H
#define SOCKS5_SERVER_H

#include <sys/socket.h>

#include <event2/listener.h>
#include <event2/dns.h>

#include "socks5_auth_manager.h"

struct socks5server;

struct socks5server *socks5server_new(struct event_base *base,
        const struct sockaddr *servaddr, int addrlen,
        struct s5auth_manager *auth_manager, struct evdns_base *dns_base);
void socks5server_free(struct socks5server *serv);

int socks5server_gen_id(struct socks5server *serv);

struct event_base *socks5server_get_event_base(struct socks5server *serv);
struct s5auth_manager *socks5server_get_auth_manager(struct socks5server *serv);
struct evdns_base *socks5server_get_dns_base(struct socks5server *serv);

#endif /* ifndef SOCKS5_SERVER_H */
