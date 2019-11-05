#ifndef SOCKS5_BIND_PROCESSOR_H
#define SOCKS5_BIND_PROCESSOR_H

#include <event2/bufferevent.h>
#include <event2/listener.h>

/* forward declarations */
struct socks5tunnel;

/* The processor that handles socks5 BIND command */
struct s5bind_processor;

struct s5bind_processor *s5bind_processor_new(struct event_base *evbase,
        struct socks5tunnel *tunnel, long tunnel_id);
void s5bind_processor_free(struct s5bind_processor *processor);

void s5bind_processor_start(struct s5bind_processor *processor);
int s5bind_processor_write(struct s5bind_processor *processor, struct evbuffer *buffer);
void s5bind_processor_shutdown_write(struct s5bind_processor *processor);


/* callbacks:
 * listen success/fail
 * accept success/fail
 * data_received/write_completed
 * eof/read_error/write_error
 */
typedef void (*s5bind_processor_on_bind_success_cb)(struct socks5tunnel *tunnel, const struct sockaddr *addr, socklen_t addrlen);
typedef void (*s5bind_processor_on_bind_error_cb)(struct socks5tunnel *tunnel);

typedef void (*s5bind_processor_on_connection_success_cb)(struct socks5tunnel *tunnel, const struct sockaddr *addr, socklen_t addrlen);
typedef void (*s5bind_processor_on_connection_error_cb)(struct socks5tunnel *tunnel);

typedef void (*s5bind_processor_on_data_received_cb)(struct socks5tunnel *tunnel, struct evbuffer *buffer);
typedef void (*s5bind_processor_on_data_write_completed_cb)(struct socks5tunnel *tunnel);
typedef void (*s5bind_processor_on_eof_cb)(struct socks5tunnel *tunnel);
typedef void (*s5bind_processor_on_read_error_cb)(struct socks5tunnel *tunnel);
typedef void (*s5bind_processor_on_write_error_cb)(struct socks5tunnel *tunnel);

/* callback setters */
void s5bind_processor_set_on_bind_success_cb(struct s5bind_processor *processor,
        s5bind_processor_on_bind_success_cb cb);
void s5bind_processor_set_on_bind_error_cb(struct s5bind_processor *processor,
        s5bind_processor_on_bind_error_cb cb);

void s5bind_processor_set_on_connection_success_cb(struct s5bind_processor *processor,
        s5bind_processor_on_connection_success_cb cb);
void s5bind_processor_set_on_connection_error_cb(struct s5bind_processor *processor,
        s5bind_processor_on_connection_error_cb cb);

void s5bind_processor_set_on_data_received_cb(struct s5bind_processor *processor,
        s5bind_processor_on_data_received_cb cb);
void s5bind_processor_set_on_data_write_completed_cb(struct s5bind_processor *processor,
        s5bind_processor_on_data_write_completed_cb cb);

void s5bind_processor_set_on_eof_cb(struct s5bind_processor *processor,
        s5bind_processor_on_eof_cb cb);
void s5bind_processor_set_on_read_error_cb(struct s5bind_processor *processor,
        s5bind_processor_on_read_error_cb cb);
void s5bind_processor_set_on_write_error_cb(struct s5bind_processor *processor,
        s5bind_processor_on_write_error_cb cb);

#endif /* ifndef SOCKS5_BIND_PROCESSOR_H */
