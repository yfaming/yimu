#include <error.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <event2/event.h>

#include "logging.h"
#include "socks5_auth_manager.h"
#include "socks5_server.h"
#include "util.h"

static void libevent_log_wrapper(int severity, const char *msg);
static struct s5auth_manager *init_auth_manager();
static struct evdns_base *init_dns(struct event_base *evbase);

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;
    signal(SIGPIPE, SIG_IGN);
    event_set_log_callback(libevent_log_wrapper);

    struct s5auth_manager *auth_manager = NULL;
    struct event_base *evbase = NULL;
    struct evdns_base *dns_base = NULL;
    struct socks5server *serv = NULL;

    if ((auth_manager = init_auth_manager()) == NULL) {
        error("s5auth_manager_new() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }

    if ((evbase = event_base_new()) == NULL) {
        error("event_base_new() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }

    if ((dns_base = init_dns(evbase)) == NULL) {
        error("init_dns() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(2019);
    if ((serv = socks5server_new(evbase, (struct sockaddr *)&servaddr, sizeof(servaddr), auth_manager, dns_base)) == NULL) {
        error("socks5server_new() failed.");
        goto FAIL;
    }

    /* run */
    info("starting event base");
    event_base_dispatch(evbase);
    warn("event base stopped");

    socks5server_free(serv);
    evdns_base_free(dns_base, 1);
    event_base_free(evbase);
    /* serv references, but does not own auth_manager */
    s5auth_manager_free(auth_manager);
    return 0;

FAIL:
    if (serv)
        socks5server_free(serv);
    if (dns_base)
        evdns_base_free(dns_base, 1);
    if (evbase)
        event_base_free(evbase);
    if (auth_manager)
        s5auth_manager_free(auth_manager);
    return 1;
}

static void libevent_log_wrapper(int severity, const char *msg)
{
    int level;
    const char *file = "<Libevent>";
    int line = 0;
    const char *func = "<unknown>";
    switch (severity) {
        case EVENT_LOG_DEBUG: level = DEBUG; break;
        case EVENT_LOG_MSG: level = INFO; break;
        case EVENT_LOG_WARN: level = WARN; break;
        case EVENT_LOG_ERR: level = ERROR; break;
        default: return;
    }
    ymlog(level, file, line, func, msg);
}


static struct s5auth_manager *init_auth_manager()
{
    /* can get username/password from command line options */
    struct identity identities[] = {
        {"uyfaming", "pyfaming"},
    };
    size_t n = sizeof(identities) / sizeof(identities[0]);

    struct s5auth_manager *auth_manager = s5auth_manager_new();
    if (auth_manager == NULL) {
        error("s5auth_manager_new() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }
    if (s5auth_manager_register_no_auth_authenticator(auth_manager) == -1) {
        error("s5auth_manager_register_no_auth_authenticator() failed: %s (errno=%d)",
                strerror(errno), errno);
        goto FAIL;
    }
    if (s5auth_manager_register_username_password_authenticator(auth_manager, identities, n) == -1) {
        error("s5auth_manager_register_username_password_authenticator() failed: %s (errno=%d)",
                strerror(errno), errno);
        goto FAIL;
    }
    return auth_manager;

FAIL:
    if (auth_manager)
        s5auth_manager_free(auth_manager);
    return NULL;
}

static struct evdns_base *init_dns(struct event_base *evbase)
{
    /* initialize=0, leaves the evdns_base empty, with no nameservers or options configured. */
    struct evdns_base *dns_base = NULL;
    dns_base = evdns_base_new(evbase, 0);
    if (dns_base == NULL) {
        error("evdns_base_new() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }

    /* use google's dns server */
    if (evdns_base_nameserver_ip_add(dns_base, "8.8.8.8") == -1) {
        error("evdns_base_nameserver_ip_add() failed: %s (errno=%d)", strerror(errno), errno);
        goto FAIL;
    }

    /* load hosts file, like /etc/hosts. */
    if (evdns_base_load_hosts(dns_base, "/etc/hosts") == -1) {
        error("evdns_base_load_hosts() failed: %s (errno=%d)", strerror(errno), errno);
        /* we just ignore this error */
    }
    return dns_base;

FAIL:
    if (dns_base)
        event_base_free(evbase);
    return NULL;
}
