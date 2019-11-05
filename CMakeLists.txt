cmake_minimum_required (VERSION 3.1.0)
project (yimu C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(Libevent REQUIRED)
include_directories("${LIBEVENT_INCLUDE_DIRS}")

find_package(Threads REQUIRED)

add_executable(yimulocal
	logging.c
	socks5_authenticator.c
	socks5_auth_manager.c
	socks5_bind_processor.c
	socks5_conn.c
	socks5_no_auth_authenticator.c
	socks5_protocol.c
	socks5_proxy.c
	socks5_proxy_dummy.c
	socks5_server.c
	socks5_tunnel.c
	socks5_udp_associate_processor.c
	socks5_username_password_authenticator.c
	util.c
	yimu_local.c
)
target_link_libraries(yimulocal ${LIBEVENT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
