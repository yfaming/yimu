#ifndef SOCKS5_PROXY_H
#define SOCKS5_PROXY_H
#include <errno.h>
#include <stdlib.h>

#include <event2/buffer.h>
#include <event2/util.h>

#include "socks5_protocol.h"
#include "logging.h"

/* forward declarations */
struct proxy;
struct socks5tunnel;


/* callback typedefs for proxy */
typedef void (*on_connection_succeess_cb)(struct socks5tunnel *tunnel, const struct sockaddr *addr, socklen_t addrlen);
typedef void (*on_connection_error_cb)(struct socks5tunnel *tunnel);
typedef void (*on_data_received_cb)(struct socks5tunnel *tunnel, struct evbuffer *buffer);
typedef void (*on_data_write_completed_cb)(struct socks5tunnel *tunnel);
typedef void (*on_eof_cb)(struct socks5tunnel *tunnel);
typedef void (*on_read_error_cb)(struct socks5tunnel *tunnel);
typedef void (*on_write_error_cb)(struct socks5tunnel *tunnel);

struct proxy_ops {
    void (*set_connection_success_cb)(struct proxy *proxy, on_connection_succeess_cb cb);
    void (*set_connection_error_cb)(struct proxy *proxy, on_connection_error_cb cb);
    void (*set_data_received_cb)(struct proxy *proxy, on_data_received_cb cb);
    void (*set_data_write_completed_cb)(struct proxy *proxy, on_data_write_completed_cb cb);
    void (*set_eof_cb)(struct proxy *proxy, on_eof_cb cb);
    void (*set_read_error_cb)(struct proxy *proxy, on_read_error_cb cb);
    void (*set_write_error_cb)(struct proxy *proxy, on_write_error_cb cb);

    void (*imp_free)(void *imp);
    void (*shutdown_write)(struct proxy *proxy);
    void (*connect)(struct proxy *proxy, uint8_t addr_type, const union socks5_address *dest_addr, uint16_t dest_port);
    int (*write)(struct proxy *proxy, struct evbuffer *buffer);
};

struct proxy {
    struct proxy_ops ops;
    void *imp;
    int refcnt;
};

struct proxy *proxy_new(struct proxy_ops ops, void *imp);
void proxy_free(struct proxy *proxy);

void proxy_connect(struct proxy *proxy, uint8_t addr_type, const union socks5_address *dest_addr, uint16_t dest_port);
int proxy_write(struct proxy *proxy, struct evbuffer *buffer);
void proxy_shutdown_write(struct proxy *proxy);

void proxy_set_connection_success_cb(struct proxy *proxy, on_connection_succeess_cb cb);
void proxy_set_connection_error_cb(struct proxy *proxy, on_connection_error_cb cb);
void proxy_set_data_received_cb(struct proxy *proxy, on_data_received_cb cb);
void proxy_set_data_write_completed_cb(struct proxy *proxy, on_data_write_completed_cb cb);
void proxy_set_eof_cb(struct proxy *proxy, on_eof_cb cb);
void proxy_set_read_error_cb(struct proxy *proxy, on_read_error_cb cb);
void proxy_set_write_error_cb(struct proxy *proxy, on_write_error_cb cb);

void proxy_incref(struct proxy *proxy);
void proxy_decref(struct proxy *proxy);
#endif /* ifndef SOCKS5_PROXY_H */
