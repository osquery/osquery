get_source_path("gmock" gmock_source_path)

ExternalProject_Add(
  gmock
  URL https://googlemock.googlecode.com/files/gmock-1.7.0.zip
  URL_HASH SHA1=f9d9dd882a25f4069ed9ee48e70aff1b53e3c5a5
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ./configure --prefix=${third_party_prefix}
  BUILD_COMMAND make
  INSTALL_COMMAND ${third_party_mkdir} && cp -R ${gmock_source_path}/include/gmock ${third_party_include} && cp ${gmock_source_path}/lib/libgmock.la ${third_party_lib}
)
