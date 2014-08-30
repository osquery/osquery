INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/third-party/rocksdb/include")
include(ExternalProject)
ExternalProject_Add(librocksdb
  SOURCE_DIR "${CMAKE_SOURCE_DIR}/third-party/rocksdb"
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make shared_lib && make static_lib
  INSTALL_COMMAND cp librocksdb.dylib /usr/local/lib/librocksdb.dylib && cp librocksdb.a /usr/local/lib/librocksdb.a
)
