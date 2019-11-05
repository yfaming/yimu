#ifndef UTIL_H
#define UTIL_H

#include <sys/socket.h>
#include <sys/types.h>

/* sockaddr_ntop converts IPv4 and IPv6 socket address from binary to text form.
 * returns 0 on success, -1 on error and errno is set appropriately.
 *
 * The presentation format is the dotted-decimal form of an IPv4 address or the
 * hex string form of an IPv6 address surrounded by brackets, followed by a
 * colon, followed by the decimal port number, followed by NUL.
 *
 * bufsize must be at least INET_ADDRSTRLEN + 6(16 + 6 = 22) for IPv4 and
 * INET6_ADDRSTRLEN + 8(46 + 8 = 54) for IPv4.
 * use macro SOCKADDR_STRLEN below for convenience.
 */
int sockaddr_ntop(const struct sockaddr *addr, char *buf, size_t bufsize);
#define SOCKADDR_STRLEN 54

/* compare 2 sockaddr, return 0 if addr1 equals addr2, and returns nonzero otherwise
 * only supports IP v4 and v6.
 */
int sockaddr_cmp(const struct sockaddr *addr1, const struct sockaddr *addr2);

char *str_bufferevent_event(int event, char *s, size_t len);

#endif /* ifndef UTIL_H */
