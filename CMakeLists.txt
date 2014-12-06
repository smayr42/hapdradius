cmake_minimum_required(VERSION 2.8.4)
project(HAPDRadius)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wall")

set(SOURCE_FILES
  utils/eloop.c
  utils/common.c
  utils/wpa_debug.c
  utils/wpabuf.c
  utils/os_unix.c
  utils/ip_addr.c
  radius/radius.c
  crypto/md5.c
  eap_server/eap_server_peap.c
  eap_common/eap_peap_common.c
  eap_server/eap_server_mschapv2.c
  eap_server/eap_server.c
  eap_common/eap_common.c
  eap_server/eap_server_methods.c
  eap_server/eap_server_identity.c
  crypto/ms_funcs.c
  eap_server/eap_server_tls_common.c
  crypto/tls_openssl.c
  crypto/crypto_openssl.c
  crypto/sha1-prf.c
  crypto/sha1-tlsprf.c
  crypto/random.c
  radius/radius_server.c
  radius.c
)

add_definitions(-DEAP_SERVER_PEAP -DEAP_SERVER_MSCHAPV2 -DEAP_SERVER_IDENTITY -DEAP_SERVER -DEAP_TLS_FUNCS -DRADIUS_SERVER)

include_directories(. utils)
add_executable(HAPDRadius ${SOURCE_FILES})

target_link_libraries(HAPDRadius -lssl -lcrypto -lsqlite3)

install(TARGETS HAPDRadius RUNTIME DESTINATION bin)
