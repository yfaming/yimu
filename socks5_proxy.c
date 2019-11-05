#include "socks5_proxy.h"

static void proxy_reset_all_cbs(struct proxy *proxy);
static void proxy_real_free(struct proxy *proxy);

struct proxy *proxy_new(struct proxy_ops ops, void *imp)
{
    struct proxy *proxy = malloc(sizeof(struct proxy));
    if (proxy == NULL) {
        error("malloc() for struct proxy failed: %s (errno=%d)", strerror(errno), errno);
        ops.imp_free(imp);
        return NULL;
    }
    proxy->ops = ops;
    proxy->imp = imp;
    proxy->refcnt = 1;
    return proxy;
}

void proxy_free(struct proxy *proxy)
{
    proxy_reset_all_cbs(proxy);
    proxy_decref(proxy);
}

void proxy_incref(struct proxy *proxy)
{
    proxy->refcnt++;
}

void proxy_decref(struct proxy *proxy)
{
    proxy->refcnt--;
    if (proxy->refcnt == 0)
        proxy_real_free(proxy);
}

static void proxy_reset_all_cbs(struct proxy *proxy)
{
    proxy->ops.set_connection_success_cb = NULL;
    proxy->ops.set_connection_error_cb = NULL;
    proxy->ops.set_data_received_cb = NULL;
    proxy->ops.set_data_write_completed_cb = NULL;
    proxy->ops.set_eof_cb = NULL;
    proxy->ops.set_read_error_cb = NULL;
    proxy->ops.set_write_error_cb = NULL;
}

static void proxy_real_free(struct proxy *proxy)
{
    proxy->ops.imp_free(proxy->imp);
    free(proxy);
}


void proxy_connect(struct proxy *proxy, uint8_t addr_type, const union socks5_address *dest_addr, uint16_t dest_port)
{
    proxy->ops.connect(proxy, addr_type, dest_addr, dest_port);
}

int proxy_write(struct proxy *proxy, struct evbuffer *buffer)
{
    return proxy->ops.write(proxy, buffer);
}

void proxy_shutdown_write(struct proxy *proxy)
{
    proxy->ops.shutdown_write(proxy);
}

void proxy_set_connection_success_cb(struct proxy *proxy, on_connection_succeess_cb cb)
{
    proxy->ops.set_connection_success_cb(proxy, cb);
}

void proxy_set_connection_error_cb(struct proxy *proxy, on_connection_error_cb cb)
{
    proxy->ops.set_connection_error_cb(proxy, cb);
}

void proxy_set_data_received_cb(struct proxy *proxy, on_data_received_cb cb)
{
    proxy->ops.set_data_received_cb(proxy, cb);
}

void proxy_set_data_write_completed_cb(struct proxy *proxy, on_data_write_completed_cb cb)
{
    proxy->ops.set_data_write_completed_cb(proxy, cb);
}

void proxy_set_eof_cb(struct proxy *proxy, on_eof_cb cb)
{
    proxy->ops.set_eof_cb(proxy, cb);
}

void proxy_set_read_error_cb(struct proxy *proxy, on_read_error_cb cb)
{
    proxy->ops.set_read_error_cb(proxy, cb);
}

void proxy_set_write_error_cb(struct proxy *proxy, on_write_error_cb cb)
{
    proxy->ops.set_write_error_cb(proxy, cb);
}
