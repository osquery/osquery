set(CPP-NETLIB_SOURCE_DIR "${CMAKE_SOURCE_DIR}/third-party/cpp-netlib")
set(CPP-NETLIB_BUILD_DIR "${CMAKE_BINARY_DIR}/third-party/cpp-netlib")

# Only build the cpp-netlib shared library.
SET(CPP-NETLIB_BUILD_TESTS OFF)
SET(CPP-NETLIB_BUILD_EXAMPLES OFF)
SET(CPP-NETLIB_BUILD_SHARED_LIBS OFF)

INCLUDE_DIRECTORIES("${CPP-NETLIB_SOURCE_DIR}")
ADD_SUBDIRECTORY("${CPP-NETLIB_SOURCE_DIR}")

SET(CPP-NETLIB_LINK_DIR "${CPP-NETLIB_BUILD_DIR}/libs/network/src")
SET(CPP-NETLIB_LIBRARY
  "${CPP-NETLIB_LINK_DIR}/libcppnetlib-uri.a"
  "${CPP-NETLIB_LINK_DIR}/libcppnetlib-client-connections.a"
  "${CPP-NETLIB_LINK_DIR}/libcppnetlib-server-parsers.a"
)
