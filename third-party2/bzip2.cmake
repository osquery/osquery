get_source_path("bzip2" bzip2_source_path)

ExternalProject_Add(
  bzip2
  URL http://www.bzip.org/1.0.6/bzip2-1.0.6.tar.gz
  URL_HASH SHA1=3f89f861209ce81a6bab1fd1998c0ef311712002
  SOURCE_DIR ${bzip2_source_path}
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND true
  BUILD_COMMAND make CFLAGS=-fPIC
  INSTALL_COMMAND make install PREFIX=${third_party_prefix}
)
