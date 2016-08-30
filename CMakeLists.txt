cmake_minimum_required(VERSION 3.2)
include(ExternalProject)

project(hapdradius)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wall -Os -flto")

set(HOSTAPD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/src/hostapd")
set(HOSTAPD_SOURCE_FILES
    ${HOSTAPD_DIR}/src/utils/eloop.c
    ${HOSTAPD_DIR}/src/utils/common.c
    ${HOSTAPD_DIR}/src/utils/wpa_debug.c
    ${HOSTAPD_DIR}/src/utils/wpabuf.c
    ${HOSTAPD_DIR}/src/utils/os_unix.c
    ${HOSTAPD_DIR}/src/utils/ip_addr.c
    ${HOSTAPD_DIR}/src/eap_common/eap_common.c
    ${HOSTAPD_DIR}/src/eap_common/eap_peap_common.c
    ${HOSTAPD_DIR}/src/eap_server/eap_server.c
    ${HOSTAPD_DIR}/src/eap_server/eap_server_peap.c
    ${HOSTAPD_DIR}/src/eap_server/eap_server_mschapv2.c
    ${HOSTAPD_DIR}/src/eap_server/eap_server_methods.c
    ${HOSTAPD_DIR}/src/eap_server/eap_server_identity.c
    ${HOSTAPD_DIR}/src/eap_server/eap_server_tls_common.c
    ${HOSTAPD_DIR}/src/crypto/ms_funcs.c
    ${HOSTAPD_DIR}/src/crypto/tls_openssl.c
    ${HOSTAPD_DIR}/src/crypto/crypto_openssl.c
    ${HOSTAPD_DIR}/src/crypto/sha1-prf.c
    ${HOSTAPD_DIR}/src/crypto/sha1-tlsprf.c
    ${HOSTAPD_DIR}/src/crypto/sha256-tlsprf.c
    ${HOSTAPD_DIR}/src/crypto/random.c
    ${HOSTAPD_DIR}/src/radius/radius.c
    ${HOSTAPD_DIR}/src/radius/radius_server.c
    ${HOSTAPD_DIR}/hostapd/eap_register.c
    )

set(HOSTAPD_RELEASE 2.5)
ExternalProject_Add(hostapd
    URL https://w1.fi/releases/hostapd-${HOSTAPD_RELEASE}.tar.gz
    PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/third_party"
    PATCH_COMMAND patch -p1 -d ${HOSTAPD_DIR} < "${CMAKE_CURRENT_SOURCE_DIR}/0001-Add-callbacks-for-accounting-and-authentication.patch"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    UPDATE_COMMAND ""
    INSTALL_COMMAND ""
    TEST_COMMAND ""
    BUILD_BYPRODUCTS ${HOSTAPD_SOURCE_FILES}
    )

set(SOURCE_FILES ${HOSTAPD_SOURCE_FILES} radius.c)

find_library(SQLITE3_LIB NAMES sqlite3)
find_library(SSL_LIB NAMES ssl)
find_library(CRYPTO_LIB NAMES crypto)

include_directories(. ${HOSTAPD_DIR} ${HOSTAPD_DIR}/src ${HOSTAPD_DIR}/src/utils)

add_definitions(
    -DEAP_SERVER
    -DEAP_SERVER_IDENTITY
    -DEAP_SERVER_MSCHAPV2
    -DEAP_SERVER_PEAP
    -DRADIUS_SERVER
    -DCONFIG_DEBUG_SYSLOG
    -DCONFIG_SHA256
    )

add_executable(hapdradius ${SOURCE_FILES})
add_dependencies(hapdradius hostapd)

target_link_libraries(hapdradius ${SSL_LIB} ${CRYPTO_LIB} ${SQLITE3_LIB})

install(TARGETS hapdradius RUNTIME DESTINATION bin)
