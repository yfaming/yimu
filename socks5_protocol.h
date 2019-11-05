#ifndef SOCKS5_PROTOCOL_H
#define SOCKS5_PROTOCOL_H

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

#include <event2/buffer.h>

/* Life cycle of socks5 session are divided into 4 stages, first 3 of which are request-reply mode.
 *
 * SOCKS5_STAGE_NEGOTIATION: client send auth negotiation request and server replies with auth
 * negotiation reply. The client should terminate the TCP connection when it receives a reply
 * indicating that no auth methods are acceptable.
 *
 * SOCKS5_STAGE_AUTHENTICATION: the selected authenticator takes over the session. It will do
 * whatever it needs to authenticate the session, regardless how and how much data both ends need
 * to exchange. (RFC1928 does not speicify whether the client or the server should terminate the
 * TCP connection if authentication fails. We just always let the server to do the connection
 * termination.)
 *
 * SOCKS5_STAGE_REQUEST_PROCESS: the client sends the proxy request and the server replies with 1
 * or 2 replies depending on request's CMD field. CMD field can take 3 possible vaules: CONNECT,
 * BIND, or UDP ASSOCIATE. CONNECT and UDP ASSOCIATE requests have 2 replies, and BIND rquest have 2.
 * If the reply indicates a failure, the server must terminate the TCP connection after sending the
 * reply.
 *
 * SOCKS5_STAGE_PROXY: The tunnel receives data from one end and send it unchanged to the other end.
 */
enum socks5_stage {
    SOCKS5_STAGE_NEGOTIATION,
    SOCKS5_STAGE_AUTHENTICATION,
    SOCKS5_STAGE_REQUEST_PROCESS,
    SOCKS5_STAGE_PROXY
};

enum {
    YM_SUCCESS = 0,
    YM_ERROR = -1,
    YM_NEED_MORE_DATA = 2,
};

#define SOCKS_V5 5

#define SOCKS5_AUTH_METHOD_NO_AUTH_REQUIRED       0  /* no auth */
#define SOCKS5_AUTH_METHOD_GSSAPI                 1  /* GSSAPI */
#define SOCKS5_AUTH_METHOD_USERNAME_PASSWORD      2  /* username/password */
#define SOCKS5_AUTH_METHOD_NO_ACCEPTABLE_METHOD 255  /* no acceptable method */

struct s5_auth_negotiation_request {
    uint8_t version;
    uint8_t n_methods;
    uint8_t methods[255]; /* only [0, n_methods - 1] are useful */
};

struct s5_auth_negotiation_reply {
    uint8_t version;
    uint8_t method;
};

int evbuffer_read_s5_auth_negotiation_request(struct evbuffer *buffer, struct s5_auth_negotiation_request *req);
int evbuffer_write_s5_auth_negotiation_reply(struct evbuffer *buffer, const struct s5_auth_negotiation_reply *res);

#define SOCKS5_CMD_CONNECT       1
#define SOCKS5_CMD_BIND          2
#define SOCKS5_CMD_UDP_ASSOCIATE 3

/* address type */
#define SOCKS5_ATYPE_IPV4       1
#define SOCKS5_ATYPE_DOMAINNAME 3
#define SOCKS5_ATYPE_IPV6       4

union socks5_address {
    struct in_addr ipv4;
    /* contains domain name only with terminating NULL
     * The first byte indicating domain name length excluded
     */
    char domain[256];
    struct in6_addr ipv6;
};


struct s5_request {
    uint8_t version;   /* always 5 */
    uint8_t cmd;       /* SOCKS5_CMD_xxx */
    uint8_t rsv;       /* always 0 */
    uint8_t addr_type; /* SOCKS5_ATYPE_xxx */
    union socks5_address dest_addr;
    uint16_t dest_port; /* host order */
};

/* reply code */
#define SOCKS5_REP_SUCCEEDED                  0
#define SOCKS5_REP_GENERAL_FAILURE            1
#define SOCKS5_REP_CONNECTION_NOT_ALLOWED     2
#define SOCKS5_REP_NETWORK_UNREACHABLE        3
#define SOCKS5_REP_HOST_UNREACHABLE           4
#define SOCKS5_REP_CONNECTION_REFUSED         5
#define SOCKS5_REP_TTL_EXPIRED                6
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED      7
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 8
/* 9 - 255 not assigned */

struct s5_reply {
    uint8_t version;   /* always 5   */
    uint8_t reply;     /* reply code */
    uint8_t rsv;       /* always 0   */
    uint8_t addr_type; /* SOCKS5_ATYPE_xxx */
    union socks5_address bind_addr;
    uint16_t bind_port; /* host order */
};

/* When YM_ERROR returned, reply_code is set to one of SOCKS5_REP_xxx code */
int evbuffer_read_s5_request(struct evbuffer *buffer, struct s5_request *req, uint8_t *reply_code);
/* returns a pointer to dynamically allocated string representation of s5_request, or NULL on error */
char *strs5request(struct s5_request *req);

void s5_reply_init(struct s5_reply *s5reply, uint8_t reply_code, const struct sockaddr *sockaddr);
int evbuffer_write_s5_reply(struct evbuffer *buffer, const struct s5_reply *res);


/* UDP associate not supported for now */
struct s5_udp_request {
    uint16_t rsv;      /* always 0 */
    uint8_t frag;
    uint8_t addr_type; /* SOCKS5_ATYPE_xxx */
    union socks5_address dest_addr;
    uint16_t dest_port; /* host order */
    char *data;
    int datalen;
};

/* on success, s5_udp_request.data points to internal space with buf. We do not malloc space */
int read_s5_udp_request(char *buf, size_t buflen, struct s5_udp_request *req);

#endif /* ifndef SOCKS5_PROTOCOL_H */
