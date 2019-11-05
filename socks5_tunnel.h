#ifndef SOCKS5_TUNNEL_H
#define SOCKS5_TUNNEL_H

#include <event2/event.h>

#include "socks5_server.h"

struct socks5tunnel *socks5tunnel_new(struct socks5server *serv, evutil_socket_t connfd,
        struct sockaddr *peeraddr, int addrlen);

void socks5tunnel_free(struct socks5tunnel *tunnel);

long socks5tunnel_get_id(struct socks5tunnel *tunnel);

#endif /* ifndef SOCKS5_TUNNEL_H */
