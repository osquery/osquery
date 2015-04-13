SET(CPP-NETLIB_BUILD_TESTS false)
ADD_DEFINITIONS(-DBOOST_NETWORK_ENABLE_HTTPS)
ADD_SUBDIRECTORY("${CMAKE_SOURCE_DIR}/third-party/cpp-netlib")
INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/third-party/cpp-netlib")
SET(CPP-NETLIB_LINK_DIR "${PROJECT_BINARY_DIR}/third-party/cpp-netlib/libs/network/src")
SET(CPP-NETLIB_LIBRARY
  "${CPP-NETLIB_LINK_DIR}/libcppnetlib-uri.a"
  "${CPP-NETLIB_LINK_DIR}/libcppnetlib-client-connections.a"
  "${CPP-NETLIB_LINK_DIR}/libcppnetlib-server-parsers.a"
)
