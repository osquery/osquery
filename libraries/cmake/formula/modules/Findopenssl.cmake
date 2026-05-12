# FreeBSD: use base-system OpenSSL (linked via USES=ssl)
include("${CMAKE_CURRENT_LIST_DIR}/../../source/modules/freebsd_system_libs.cmake")
freebsd_use_system_lib(openssl
  LIBS ssl crypto
  INCLUDES /usr/include
  DEFINITIONS OPENSSL_API_COMPAT=10101
)
