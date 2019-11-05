#define _ISOC99_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <event2/bufferevent.h>

int sockaddr_ntop(const struct sockaddr *addr, char *buf, size_t bufsize)
{
    char *TMPLv4 = "%s:%d";
    char *TMPLv6 = "[%s]:%d";
    char *tmpl;

    char address[INET6_ADDRSTRLEN];
    void *addrp;
    in_port_t nport = 0;

    switch (addr->sa_family) {
    case AF_INET:
        addrp = &((struct sockaddr_in *)addr)->sin_addr;
        nport = ((struct sockaddr_in *)addr)->sin_port;
        tmpl = TMPLv4;
        break;
    case AF_INET6:
        addrp = &((struct sockaddr_in6 *)addr)->sin6_addr;
        nport = ((struct sockaddr_in6 *)addr)->sin6_port;
        tmpl = TMPLv6;
        break;
    default:
        errno = EAFNOSUPPORT;
        return -1;
    }

    nport = ntohs(nport);
    if (inet_ntop(addr->sa_family, addrp, address, sizeof(address)) == NULL)
        return -1;

    snprintf(buf, bufsize, tmpl, address, nport);
    return 0;
}

int sockaddr_cmp(const struct sockaddr *addr1, const struct sockaddr *addr2)
{
    assert(addr1 != NULL);
    assert(addr2 != NULL);
    if (addr1->sa_family != addr2->sa_family)
        return -1;

    int domain = addr1->sa_family;
    assert(domain == AF_INET || domain == AF_INET6);
    if (domain == AF_INET) {
        struct sockaddr_in *in_addr1 = (struct sockaddr_in *)addr1;
        struct sockaddr_in *in_addr2 = (struct sockaddr_in *)addr2;
        if (in_addr1->sin_addr.s_addr == in_addr2->sin_addr.s_addr
                && in_addr1->sin_port == in_addr2->sin_port)
            return 0;
        return -1;
    } else {  /* AF_INET6 */
        struct sockaddr_in6 *in6_addr1 = (struct sockaddr_in6 *)addr1;
        struct sockaddr_in6 *in6_addr2 = (struct sockaddr_in6 *)addr2;
        if (memcmp(&in6_addr1->sin6_addr, &in6_addr2->sin6_addr, sizeof(struct in6_addr)) == 0
                && in6_addr1->sin6_port == in6_addr2->sin6_port)
            return 0;
        return -1;
    }
}


char *str_bufferevent_event(int event, char *s, size_t len)
{
    struct entry {
        int evflag;
        char *evname;
    };

    struct entry entries[] = {
        {BEV_EVENT_READING, "BEV_EVENT_READING"},
        {BEV_EVENT_WRITING, "BEV_EVENT_WRITING"},
        {BEV_EVENT_ERROR, "BEV_EVENT_ERROR"},
        {BEV_EVENT_TIMEOUT, "BEV_EVENT_TIMEOUT"},
        {BEV_EVENT_EOF, "BEV_EVENT_EOF"},
        {BEV_EVENT_CONNECTED, "BEV_EVENT_CONNECTED"}
    };

    char buf[128];
    buf[0] = '\0';
    size_t i;
    for (i = 0; i < sizeof(entries)/sizeof(struct entry); i++) {
        if (event & entries[i].evflag) {
            if (buf[0] != '\0')
                strcat(buf, "|");
            strcat(buf, entries[i].evname);
        }
    }
    strncpy(s, buf, len);
    return s;
}
