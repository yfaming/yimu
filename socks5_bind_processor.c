#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"
#include "socks5_bind_processor.h"
#include "util.h"

static void socks5bind_processor_incref(struct s5bind_processor *processor);
static void socks5bind_processor_decref(struct s5bind_processor *processor);
static void socks5bind_processor_reset_all_cbs(struct s5bind_processor *processor);
static void socks5bind_processor_real_free(struct s5bind_processor *processor);

struct s5bind_processor {
    struct evconnlistener *listener;
    struct bufferevent *bev;
    int write_is_shutdown;

    struct event_base *evbase;
    long tunnel_id;
    struct socks5tunnel *tunnel;

    int refcnt;

    s5bind_processor_on_bind_success_cb on_bind_success_cb;
    s5bind_processor_on_bind_error_cb on_bind_error_cb;

    s5bind_processor_on_connection_success_cb on_connection_success_cb;
    s5bind_processor_on_connection_error_cb on_connection_error_cb;

    s5bind_processor_on_data_received_cb on_data_received_cb;
    s5bind_processor_on_data_write_completed_cb on_data_write_completed_cb;
    s5bind_processor_on_eof_cb on_eof_cb;
    s5bind_processor_on_read_error_cb on_read_error_cb;
    s5bind_processor_on_write_error_cb on_write_error_cb;
};

struct s5bind_processor *s5bind_processor_new(struct event_base *evbase,
        struct socks5tunnel *tunnel, long tunnel_id)
{
    struct s5bind_processor *processor = NULL;
    processor = malloc(sizeof(struct s5bind_processor));
    if (processor == NULL) {
        error("malloc() for struct s5bind_processor failed: %s (errno=%d)", strerror(errno), errno);
        return NULL;
    }

    memset(processor, 0, sizeof(struct s5bind_processor));
    processor->evbase = evbase;
    processor->tunnel_id = tunnel_id;
    processor->tunnel = tunnel;
    processor->refcnt = 1;
    return processor;
}

void s5bind_processor_free(struct s5bind_processor *processor)
{
    socks5bind_processor_reset_all_cbs(processor);
    socks5bind_processor_decref(processor);
}


static void socks5bind_processor_incref(struct s5bind_processor *processor)
{
    processor->refcnt++;
}

static void socks5bind_processor_decref(struct s5bind_processor *processor)
{
    processor->refcnt--;
    if (processor->refcnt == 0)
        socks5bind_processor_real_free(processor);
}

static void socks5bind_processor_reset_all_cbs(struct s5bind_processor *processor)
{
    processor->on_bind_success_cb = NULL;
    processor->on_bind_error_cb = NULL;

    processor->on_connection_success_cb = NULL;
    processor->on_connection_error_cb = NULL;

    processor->on_data_received_cb = NULL;
    processor->on_data_write_completed_cb = NULL;
    processor->on_eof_cb = NULL;
    processor->on_read_error_cb = NULL;
    processor->on_write_error_cb = NULL;
}

static void socks5bind_processor_real_free(struct s5bind_processor *processor)
{
    if (processor->listener)
        evconnlistener_free(processor->listener);
    if (processor->bev)
        bufferevent_free(processor->bev);
    free(processor);
}


/* callbacks for listener */
void _listener_cb(struct evconnlistener *listener, evutil_socket_t connfd,
        struct sockaddr *sa, int socklen, void *user_arg);
void _listener_error_cb(struct evconnlistener *listener, void *user_arg);

/* callbacks for accepted connection */
void _conn_read_cb(struct bufferevent *bev, void *user_arg);
void _conn_write_cb(struct bufferevent *bev, void *user_arg);
void _conn_event_cb(struct bufferevent *bev, short events, void *user_arg);

void s5bind_processor_start(struct s5bind_processor *processor)
{
    debug("tunnel#%ld s5bind_processor_start", processor->tunnel_id);
    socks5bind_processor_incref(processor);

    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET; /* support IPv4 only */
    sockaddr.sin_addr.s_addr = INADDR_ANY;
    sockaddr.sin_port = htons(0);
    processor->listener = evconnlistener_new_bind(processor->evbase, _listener_cb,
            processor, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, 1,
            (struct sockaddr *)&sockaddr, sizeof(sockaddr));

    if (processor->listener == NULL) {
        error("tunnel#%ld evconnlistener_new_bind() failed: %s (errno=%d)",
                processor->tunnel_id, strerror(errno), errno);
        if (processor->on_bind_error_cb)
            processor->on_bind_error_cb(processor->tunnel);
    } else {
        evconnlistener_set_error_cb(processor->listener, _listener_error_cb);

        memset(&sockaddr, 0, sizeof(sockaddr));
        socklen_t addrlen = sizeof(sockaddr);
        int n = getsockname(evconnlistener_get_fd(processor->listener),
                (struct sockaddr *)&sockaddr, &addrlen);
        if (n == 0) {
            if (processor->on_bind_success_cb)
                processor->on_bind_success_cb(processor->tunnel, (struct sockaddr *)&sockaddr, addrlen);
        } else {
            error("tunnel#%ld getsockname() failed: %s (errno=%d)",
                    processor->tunnel_id, strerror(errno), errno);
            if (processor->on_bind_error_cb)
                processor->on_bind_error_cb(processor->tunnel);
        }
    }

    socks5bind_processor_decref(processor);
}


int s5bind_processor_write(struct s5bind_processor *processor, struct evbuffer *buffer)
{
    debug("tunnel#%ld s5bind_processor_write", processor->tunnel_id);
    assert(processor->bev != NULL);
    assert(processor->write_is_shutdown == 0);
    return bufferevent_write_buffer(processor->bev, buffer);
}

void s5bind_processor_shutdown_write(struct s5bind_processor *processor)
{
    debug("s5bind_processor_shutdown_write");
    assert(processor->bev != NULL);
    processor->write_is_shutdown = 1;
}


void _listener_cb(struct evconnlistener *listener, evutil_socket_t connfd,
        struct sockaddr *sa, int socklen, void *user_arg)
{
    struct s5bind_processor *processor = user_arg;
    debug("tunnel#%ld _listener_cb", processor->tunnel_id);
    socks5bind_processor_incref(processor);

    /* We only need to accept 1 connection */
    evconnlistener_free(listener);
    processor->listener = NULL;

    processor->bev = bufferevent_socket_new(processor->evbase, connfd, BEV_OPT_CLOSE_ON_FREE);
    if (processor->bev == NULL) {
        error("tunnel#%ld bufferevent_socket_new() failed: %s (errno=%d)",
                processor->tunnel_id, strerror(errno), errno);
        if (processor->on_connection_error_cb) {
            debug("tunnel#%ld on_connection_error_cb", processor->tunnel_id);
            processor->on_connection_error_cb(processor->tunnel);
        }
    } else {
        bufferevent_setcb(processor->bev, _conn_read_cb, _conn_write_cb, _conn_event_cb, processor);
        if (processor->on_connection_success_cb) {
            debug("tunnel#%ld on_connection_success_cb", processor->tunnel_id);
            processor->on_connection_success_cb(processor->tunnel, sa, socklen);
        }
    }

    socks5bind_processor_decref(processor);
}

void _listener_error_cb(struct evconnlistener *listener, void *user_arg)
{
    (void)listener;
    struct s5bind_processor *processor = user_arg;
    debug("tunnel#%ld _listener_error_cb", processor->tunnel_id);
    socks5bind_processor_incref(processor);
    if (processor->on_connection_error_cb) {
        error("tunnel#%ld on_connection_error_cb", processor->tunnel_id);
        processor->on_connection_error_cb(processor->tunnel);
    }
    socks5bind_processor_decref(processor);
}


void _conn_read_cb(struct bufferevent *bev, void *user_arg)
{
    struct s5bind_processor *processor = user_arg;
    debug("tunnel#%ld _conn_readcb: data received", processor->tunnel_id);
    socks5bind_processor_incref(processor);
    if (processor->on_data_received_cb)
        processor->on_data_received_cb(processor->tunnel, bufferevent_get_input(bev));
    socks5bind_processor_decref(processor);
}

void _conn_write_cb(struct bufferevent *bev, void *user_arg)
{
    (void)bev;
    struct s5bind_processor *processor = user_arg;
    debug("tunnel#%ld _conn_write_cb: data write completed", processor->tunnel_id);
    socks5bind_processor_incref(processor);

    if (processor->write_is_shutdown) {
        /* do real shutdown only when buffer is emptied */
        int n = shutdown(bufferevent_getfd(processor->bev), SHUT_WR);
        if (n == -1)
            error("tunnel#%ld shutdown failed: %s (errno=%d)",
                    processor->tunnel_id, strerror(errno), errno);
    }

    if (processor->on_data_write_completed_cb)
        processor->on_data_write_completed_cb(processor->tunnel);
    socks5bind_processor_decref(processor);
}

void _conn_event_cb(struct bufferevent *bev, short event, void *user_arg)
{
    (void)bev;
    struct s5bind_processor *processor = user_arg;

    char eventstr[128];
    str_bufferevent_event(event, eventstr, sizeof(eventstr));
    debug("tunnel#%ld s5bind_processor: event: %s", processor->tunnel_id, eventstr);
    socks5bind_processor_incref(processor);

    if (event & BEV_EVENT_EOF) {
        info("tunnel#%ld bind processor: connection EOF encountered", processor->tunnel_id);
        if (processor->on_eof_cb)
            processor->on_eof_cb(processor->tunnel);
    }
    if (event & BEV_EVENT_ERROR) {
        if (event & BEV_EVENT_READING) {
            error("tunnel#%ld bind processor: connection read error", processor->tunnel_id);
            if (processor->on_read_error_cb)
                processor->on_read_error_cb(processor->tunnel);
        } else {
            error("tunnel#%ld bind processor: connection write error", processor->tunnel_id);
            if (processor->on_write_error_cb)
                processor->on_write_error_cb(processor->tunnel);
        }
    }
    /* no possible: BEV_EVENT_CONNECTED|BEV_EVENT_TIMEOUT*/

    socks5bind_processor_decref(processor);
}


void s5bind_processor_set_on_bind_success_cb(struct s5bind_processor *processor,
        s5bind_processor_on_bind_success_cb cb)
{
    processor->on_bind_success_cb = cb;
}

void s5bind_processor_set_on_bind_error_cb(struct s5bind_processor *processor,
        s5bind_processor_on_bind_error_cb cb)
{
    processor->on_bind_error_cb = cb;
}

void s5bind_processor_set_on_connection_success_cb(struct s5bind_processor *processor,
        s5bind_processor_on_connection_success_cb cb)
{
    processor->on_connection_success_cb = cb;
}

void s5bind_processor_set_on_connection_error_cb(struct s5bind_processor *processor,
        s5bind_processor_on_connection_error_cb cb)
{
    processor->on_connection_error_cb = cb;
}

void s5bind_processor_set_on_data_received_cb(struct s5bind_processor *processor,
        s5bind_processor_on_data_received_cb cb)
{
    processor->on_data_received_cb = cb;
}

void s5bind_processor_set_on_data_write_completed_cb(struct s5bind_processor *processor,
        s5bind_processor_on_data_write_completed_cb cb)
{
    processor->on_data_write_completed_cb = cb;
}

void s5bind_processor_set_on_eof_cb(struct s5bind_processor *processor,
        s5bind_processor_on_eof_cb cb)
{
    processor->on_eof_cb = cb;
}

void s5bind_processor_set_on_read_error_cb(struct s5bind_processor *processor,
        s5bind_processor_on_read_error_cb cb)
{
    processor->on_read_error_cb = cb;
}

void s5bind_processor_set_on_write_error_cb(struct s5bind_processor *processor,
        s5bind_processor_on_write_error_cb cb)
{
    processor->on_write_error_cb = cb;
}
