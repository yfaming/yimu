#define _GNU_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include <event2/buffer.h>
#include "logging.h"
#include "socks5_protocol.h"

int evbuffer_read_s5_auth_negotiation_request(struct evbuffer *buffer, struct s5_auth_negotiation_request *req)
{
    size_t buflen = evbuffer_get_length(buffer);
    if (buflen < 2)
        return YM_NEED_MORE_DATA;

    uint8_t *ptr = evbuffer_pullup(buffer, 2);
    uint8_t ver = ptr[0];
    uint8_t n_methods = ptr[1];

    if (buflen < 2 + n_methods)
        return YM_NEED_MORE_DATA;

    evbuffer_drain(buffer, 2);
    evbuffer_remove(buffer, req->methods, n_methods);
    req->version = ver;
    req->n_methods = n_methods;
    return YM_SUCCESS;
}

int evbuffer_write_s5_auth_negotiation_reply(struct evbuffer *buffer, const struct s5_auth_negotiation_reply *res)
{
    if (evbuffer_add(buffer, &res->version, sizeof(res->version)) != 0)
        return YM_ERROR;
    if (evbuffer_add(buffer, &res->method, sizeof(res->method)) != 0)
        return YM_ERROR;
    return YM_SUCCESS;
}


int evbuffer_read_s5_request(struct evbuffer *buffer, struct s5_request *req, uint8_t *reply_code)
{
    /* ver, cmd, rsv, atyp take 1 byte each, summing up to 4.
     * If atyp is 3(domain name), we have to inspect the 1st byte of addr to get
     * the length of domain name.
     */
    size_t buflen = evbuffer_get_length(buffer);
    if (buflen < 5)
        return YM_NEED_MORE_DATA;

    uint8_t *ptr = evbuffer_pullup(buffer, 5);
    uint8_t addr_type = ptr[3];
    uint8_t reqlen = 0;
    uint8_t domain_name_len = 0;

    if (addr_type == SOCKS5_ATYPE_IPV4) {
        /* 4 for ver, cmd, rsv, atyp; 4 for addr; 2 for port */
        reqlen = 10;
    } else if (addr_type == SOCKS5_ATYPE_DOMAINNAME) {
        /* 4 for ver, cmd, rsv, atyp;
         * 1 for domain name length; domain_name_len for domain name
         * 2 for port
         */
        domain_name_len = ptr[4];
        reqlen = 7 + domain_name_len;
    } else if (addr_type == SOCKS5_ATYPE_IPV6) {
        /* 4 for ver, cmd, rsv, atyp; 16 for addr; 2 for port */
        reqlen = 22;
    } else {
        *reply_code = SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED;
        return YM_ERROR;
    }

    if (buflen < reqlen)
        return YM_NEED_MORE_DATA;

    if (addr_type == SOCKS5_ATYPE_DOMAINNAME && domain_name_len <= 0) {
        *reply_code = SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED;
        return YM_ERROR;
    }

    ptr = evbuffer_pullup(buffer, reqlen);
    req->version = ptr[0];
    req->cmd = ptr[1];
    req->rsv = ptr[2];
    req->addr_type = ptr[3];
    evbuffer_drain(buffer, 4);

    if (addr_type == SOCKS5_ATYPE_IPV4) {
        evbuffer_remove(buffer, &req->dest_addr.ipv4, 4);
    } else if (addr_type == SOCKS5_ATYPE_DOMAINNAME) {
        evbuffer_drain(buffer, 1); /*drop the byte for domain name length */
        evbuffer_remove(buffer, &req->dest_addr.domain, domain_name_len);
        /* there is no terminating NULL for domain name in buffer */
        req->dest_addr.domain[domain_name_len] = '\0';
    } else if (addr_type == SOCKS5_ATYPE_IPV6) {
        evbuffer_remove(buffer, &req->dest_addr.ipv6, 16);
    }
    evbuffer_remove(buffer, &req->dest_port, 2);
    req->dest_port = ntohs(req->dest_port);
    return YM_SUCCESS;
}

char *strs5request(struct s5_request *req)
{
    const char *cmd;
    if (req->cmd == SOCKS5_CMD_CONNECT)
        cmd = "CONNECT";
    else if (req->cmd == SOCKS5_CMD_BIND)
        cmd = "BIND";
    else if (req->cmd == SOCKS5_CMD_UDP_ASSOCIATE)
        cmd = "UDP_ASSOCIATE";

    char addr[256];
    if (req->addr_type == SOCKS5_ATYPE_IPV4) {
        inet_ntop(AF_INET, &req->dest_addr.ipv4, addr, sizeof(addr));
    } else if (req->addr_type == SOCKS5_ATYPE_DOMAINNAME) {
        strncpy(addr, req->dest_addr.domain, 256);
    } else {
        inet_ntop(AF_INET6, &req->dest_addr.ipv6, addr, sizeof(addr));
    }

    char *str;
    if (asprintf(&str, "s5_request {cmd:%s, addr:%s, port:%d}", cmd, addr, req->dest_port) == -1)
        return NULL;
    else
        return str;
}

void s5_reply_init(struct s5_reply *s5reply, uint8_t reply_code, const struct sockaddr *sockaddr)
{
    assert(sockaddr != NULL);
    assert(sockaddr->sa_family == AF_INET || sockaddr->sa_family == AF_INET6);
    s5reply->version = SOCKS_V5;
    s5reply->rsv = 0;
    s5reply->reply = reply_code;

    if (sockaddr->sa_family == AF_INET) {
        struct sockaddr_in *addrv4 = (struct sockaddr_in *)sockaddr;
        s5reply->addr_type = SOCKS5_ATYPE_IPV4;
        s5reply->bind_addr.ipv4 = addrv4->sin_addr;
        s5reply->bind_port = ntohs(addrv4->sin_port);
    } else {
        struct sockaddr_in6 *addrv6 = (struct sockaddr_in6 *)sockaddr;
        s5reply->addr_type = SOCKS5_ATYPE_IPV6;
        s5reply->bind_addr.ipv6 = addrv6->sin6_addr;
        s5reply->bind_port = ntohs(addrv6->sin6_port);
    }
}

int evbuffer_write_s5_reply(struct evbuffer *buffer, const struct s5_reply *res)
{
    if (evbuffer_add(buffer, &res->version, sizeof(res->version)) != 0)
        return YM_ERROR;
    if (evbuffer_add(buffer, &res->reply, sizeof(res->reply)) != 0)
        return YM_ERROR;
    if (evbuffer_add(buffer, &res->rsv, sizeof(res->rsv)) != 0)
        return YM_ERROR;
    if (evbuffer_add(buffer, &res->addr_type, sizeof(res->addr_type)) != 0)
        return YM_ERROR;

    /* write address */
    if (res->addr_type == SOCKS5_ATYPE_IPV4) {
        if (evbuffer_add(buffer, &res->bind_addr.ipv4, 4) != 0)
            return YM_ERROR;
    } else if (res->addr_type == SOCKS5_ATYPE_DOMAINNAME) {
        if (evbuffer_add(buffer, &res->bind_addr.ipv6, 16) != 0)
            return YM_ERROR;
    } else { /* SOCKS5_ATYPE_IPV6 */
        uint8_t domain_name_len = strlen(res->bind_addr.domain);
        if (evbuffer_add(buffer, &domain_name_len, sizeof(domain_name_len)) != 0)
            return YM_ERROR;
        if (evbuffer_add(buffer, res->bind_addr.domain, domain_name_len) != 0)
            return YM_ERROR;
    }

    uint16_t bind_port = htons(res->bind_port); /* convert to network order */
    if (evbuffer_add(buffer, &bind_port, sizeof(bind_port)) !=0)
        return YM_ERROR;

    return YM_SUCCESS;
}

int read_s5_udp_request(char *buf, size_t buflen, struct s5_udp_request *req)
{
    /* rsv(2) + frag(1) + atyp(1) = 4
     * If atyp is 3(domain name), the 1st byte of addr indicates the length of domain name.
     */
    if (buflen <= 5) {
        error("invalid s5_udp_request: too small to accomodate header");
        return YM_ERROR;
    }

    uint8_t addr_type = buf[3];
    if (addr_type != SOCKS5_ATYPE_IPV4 && addr_type != SOCKS5_ATYPE_IPV6 && addr_type != SOCKS5_ATYPE_DOMAINNAME) {
        error("addr_type invalid");
        return YM_ERROR;
    }

    uint8_t domain_name_len = 0;
    uint8_t headerlen = 0;
    if (addr_type == SOCKS5_ATYPE_IPV4) {
        /* rsv(2) + frag(1) + atyp(1) + dst.addr(4) + dst.port(2)  */
        headerlen = 10;
    } else if (addr_type == SOCKS5_ATYPE_DOMAINNAME) {
        /* rsv(2) + frag(1) + atyp(1) + dst.addr(domain_name_len + 1) + dst.port(2)  */
        domain_name_len = buf[4];
        headerlen = 7 + domain_name_len;
    } else if (addr_type == SOCKS5_ATYPE_IPV6) {
        /* rsv(2) + frag(1) + atyp(1) + dst.addr(16) + dst.port(2)  */
        headerlen = 22;
    }

    if (buflen < headerlen) {
        error("invalid s5_udp_request: too small to accomodate header");
        return YM_ERROR;
    }

    char *ptr = buf;
    req->rsv = *(uint16_t *)ptr; ptr += 2;
    req->frag = *ptr; ptr++;
    req->addr_type = *ptr; ptr++;

    if (addr_type == SOCKS5_ATYPE_IPV4) {
        memcpy(&req->dest_addr.ipv4, ptr, 4);
        ptr += 4;
    } else if (addr_type == SOCKS5_ATYPE_DOMAINNAME) {
        ptr++;
        memcpy(&req->dest_addr.domain, ptr, domain_name_len);
        /* there is no terminating NULL for domain name in buffer */
        req->dest_addr.domain[domain_name_len] = '\0';
        ptr += domain_name_len;
    } else if (addr_type == SOCKS5_ATYPE_IPV6) {
        memcpy(&req->dest_addr.ipv6, ptr, 16);
        ptr += 16;
    }

    req->dest_port = ntohs(*(uint16_t *)ptr); /* convert to host order */
    ptr += 2;
    req->data = ptr;
    req->datalen = buflen - headerlen;
    return YM_SUCCESS;
}
