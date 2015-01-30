ExternalProject_Add(
  zlib
  URL http://zlib.net/zlib-1.2.8.tar.gz
  URL_HASH SHA1=a4d316c404ff54ca545ea71a27af7dbc29817088
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ./configure --prefix=${third_party_prefix}
  BUILD_COMMAND make
  INSTALL_COMMAND make install
)
