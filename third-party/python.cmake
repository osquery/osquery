ExternalProject_Add(
  libpython
  URL https://www.python.org/ftp/python/2.7.9/Python-2.7.9.tgz
  URL_HASH SHA1=7a191bcccb598ccbf2fa6a0edce24a97df3fc0ad
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ./configure --prefix=${third_party_prefix}
  BUILD_COMMAND make
  INSTALL_COMMAND make install
)
