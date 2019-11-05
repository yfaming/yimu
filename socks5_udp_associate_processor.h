#ifndef SOCKS5_UDP_ASSOCIATE_PROCESSOR_H
#define SOCKS5_UDP_ASSOCIATE_PROCESSOR_H
#include <event2/bufferevent.h>
#include <event2/listener.h>

/* The udp processor here does not totally conform to RFC 1928. Because it does not support
 * the data encryption/decryption mechanism specified by the chosen authentication method.
 * We have to expose codec API of authenticator first to support it.
 */

/* forward declarations */
struct socks5tunnel;
struct s5udp_associate_processor;

struct s5udp_associate_processor *s5udp_associate_processor_new(struct event_base *evbase,
        struct evdns_base *dns_base, struct socks5tunnel *tunnel, long tunnel_id,
        const struct sockaddr *client_ip, socklen_t addrlen);
void s5udp_associate_processor_free(struct s5udp_associate_processor *processor);


/* callback declarations */
typedef void (*s5udp_associate_processor_on_success_cb)(struct socks5tunnel *tunnel,
        const struct sockaddr *serv_addr, socklen_t addrlen);
typedef void (*s5udp_associate_processor_on_error_cb)(struct socks5tunnel *tunnel);

void s5udp_associate_processor_start(struct s5udp_associate_processor *processor,
        s5udp_associate_processor_on_success_cb on_success_cb,
        s5udp_associate_processor_on_error_cb on_error_cb);


#endif /* ifndef SOCKS5_UDP_ASSOCIATE_PROCESSOR_H */
