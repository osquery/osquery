ExternalProject_Add(
  gflags
  URL https://github.com/schuhschuh/gflags/archive/v2.1.1.tar.gz
  URL_HASH SHA1=59b37548b10daeaa87a3093a11d13c2442ac6849
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=${third_party_prefix}
)
