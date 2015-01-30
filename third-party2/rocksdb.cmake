ExternalProject_Add(
  rocksdb
  URL https://github.com/facebook/rocksdb/archive/rocksdb-3.8.tar.gz
  URL_HASH SHA1=e5620ffd2520cc4ae9a2f1b2a89232dc77642b31
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND true
  BUILD_COMMAND make static_lib CXX=${CMAKE_CXX_COMPILER}
  INSTALL_COMMAND make install INSTALL_PATH=${third_party_prefix}
)
