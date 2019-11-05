#ifndef SOCKS5_CONN_H
#define SOCKS5_CONN_H
#include <event2/event.h>
#include <event2/buffer.h>

#include "socks5_auth_manager.h"
#include "socks5_protocol.h"
#include "socks5_server.h"

struct socks5conn;

struct socks5conn *socks5conn_new(struct event_base *evbase, evutil_socket_t connfd);
void socks5conn_free(struct socks5conn *conn);

int socks5conn_write_s5_auth_negotiation_reply(struct socks5conn *socks5conn,
        const struct s5_auth_negotiation_reply *res);
int socks5conn_write_s5_reply(struct socks5conn *socks5conn, const struct s5_reply *res);
int socks5conn_write_data(struct socks5conn *socks5conn, struct evbuffer *buffer);

struct socks5tunnel;
void socks5conn_set_tunnel(struct socks5conn *conn, struct socks5tunnel *tunnel, long tunnel_id);

enum socks5_stage socks5conn_get_stage(struct socks5conn *socks5conn);
void socks5conn_set_stage(struct socks5conn *socks5conn, enum socks5_stage stage);
int socks5conn_getpeername(struct socks5conn *socks5conn, struct sockaddr *addr, socklen_t *addrlen);


struct authenticator * socks5conn_choose_authenticator(struct socks5conn *socks5conn,
        struct s5auth_manager *auth_manager, const struct s5_auth_negotiation_request *req);


/* return 0 if successful, or -1 if an error occurred */
int socks5conn_stop_read(struct socks5conn *socks5conn);
void socks5conn_shutdown_write(struct socks5conn *socks5conn);

/* callbacks */
typedef void (*socks5conn_on_eof_cb)(struct socks5tunnel *tunnel);
typedef void (*socks5conn_on_read_error_cb)(struct socks5tunnel *tunnel);
typedef void (*socks5conn_on_write_error_cb)(struct socks5tunnel *tunnel);
typedef void (*socks5conn_on_write_completed_cb)(struct socks5tunnel *tunnel);

typedef void (*socks5conn_on_auth_negotiation_req_cb)(struct socks5tunnel *tunnel,
        const struct s5_auth_negotiation_request *req);
typedef void (*socks5conn_on_auth_success_cb)(struct socks5tunnel *tunnel);
typedef void (*socks5conn_on_auth_error_cb)(struct socks5tunnel *tunnel);

typedef void (*socks5conn_on_s5_request_cb)(struct socks5tunnel *tunnel,
        const struct s5_request *req);

typedef void (*socks5conn_on_data_cb)(struct socks5tunnel *tunnel, struct evbuffer *buffer);


void socks5conn_set_on_eof_cb(struct socks5conn *socks5conn, socks5conn_on_eof_cb cb);
void socks5conn_set_on_read_error_cb(struct socks5conn *socks5conn, socks5conn_on_read_error_cb cb);
void socks5conn_set_on_write_error_cb(struct socks5conn *socks5conn, socks5conn_on_write_error_cb cb);
void socks5conn_set_on_write_completed_cb(struct socks5conn *socks5conn, socks5conn_on_write_completed_cb cb);

void socks5conn_set_on_auth_negotiation_req_cb(struct socks5conn *socks5conn,
    socks5conn_on_auth_negotiation_req_cb cb);
void socks5conn_set_on_auth_success_cb(struct socks5conn *socks5conn, socks5conn_on_auth_success_cb cb);
void socks5conn_set_on_auth_error_cb(struct socks5conn *socks5conn, socks5conn_on_auth_error_cb cb);

void socks5conn_set_on_s5_request_cb(struct socks5conn *socks5conn, socks5conn_on_s5_request_cb cb);

void socks5conn_set_on_data_cb(struct socks5conn *socks5conn, socks5conn_on_data_cb cb);

#endif /* ifndef SOCKS5_CONN_H */
