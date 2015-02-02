ExternalProject_Add(
  libopenssl
  URL https://www.openssl.org/source/openssl-1.0.2.tar.gz
  URL_HASH SHA1=2f264f7f6bb973af444cd9fc6ee65c8588f610cc
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ./config --prefix=${third_party_prefix}
)
