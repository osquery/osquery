ExternalProject_Add(
  libthrift
  URL https://github.com/apache/thrift/archive/0.9.2.tar.gz
  URL_HASH SHA1=d775d8274635ccc0fc83804d53ed7c14f8608e23
  CONFIGURE_COMMAND ./bootstrap.sh && ./configure --prefix=${third_party_prefix} --with-boost=${third_party_prefix}
  DEPENDS libboost
)
