INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/third-party/rocksdb/include")
include(ExternalProject)

if (APPLE)
  set(OS_ROCKSDB_INSTALL_LIB librocksdb.dylib)
else()
  set(OS_ROCKSDB_INSTALL_LIB librocksdb.so)
endif()

ExternalProject_Add(librocksdb
  SOURCE_DIR "${CMAKE_SOURCE_DIR}/third-party/rocksdb"
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make shared_lib && make static_lib
  INSTALL_COMMAND sudo cp "${OS_ROCKSDB_INSTALL_LIB}" /usr/local/lib/ && sudo cp librocksdb.a /usr/local/lib/
)
