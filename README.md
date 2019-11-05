yimu
====

`yimu` is a full-featured socks5 server based on Libevent. It supports all the commands specified
in RFC 1928.

# Future works
* implement shadosocks proxy and more.
* integration test in a separate repo.
* low priority: redesign authenticator to make it generic enough, and expose codec API to be used in
  udp association.
* low priority: support udp fragment.
