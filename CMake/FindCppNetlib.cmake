set(CPP-NETLIB_SOURCE_DIR "${CMAKE_SOURCE_DIR}/third-party/cpp-netlib")
set(CPP-NETLIB_BUILD_DIR "${CMAKE_BINARY_DIR}/third-party/cpp-netlib")

# Only build the cpp-netlib shared library.
set(CPP-NETLIB_BUILD_TESTS OFF CACHE BOOL "")
set(CPP-NETLIB_BUILD_EXAMPLES OFF CACHE BOOL "")
set(CPP-NETLIB_BUILD_SHARED_LIBS OFF CACHE BOOL "")

include_directories("${CPP-NETLIB_SOURCE_DIR}")
add_subdirectory("${CPP-NETLIB_SOURCE_DIR}")

set(CPP-NETLIB_LINK_DIR "${CPP-NETLIB_BUILD_DIR}/libs/network/src")
set(CPP-NETLIB_LIBRARY
  "${CPP-NETLIB_LINK_DIR}/libcppnetlib-uri.a"
  "${CPP-NETLIB_LINK_DIR}/libcppnetlib-client-connections.a"
  "${CPP-NETLIB_LINK_DIR}/libcppnetlib-server-parsers.a"
)
