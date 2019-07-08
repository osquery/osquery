# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(archiveMain)
  set(name "libarchive")
  set(anchor_file "lib/libarchive.a")

  if(DEFINED PLATFORM_WINDOWS)
    set(anchor_file "lib/archive_static.lib")
  endif()

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  set(dependencies zlib)
  if(DEFINED PLATFORM_LINUX)
    list(APPEND dependencies bzip2 lzma)
  endif()

  definePrebuiltProject(${name}
    URL http://www.libarchive.org/downloads/libarchive-3.3.2.tar.gz
    SHA256 ed2dbd6954792b2c054ccf8ec4b330a54b85904a80cef477a1c74643ddafa0ce
    DEPENDS ${dependencies}
    CONFIGURE
      ./configure --prefix=<INSTALL_DIR>
        --without-lzo2
        --without-nettle
        --without-xml2
        --without-openssl
        --with-expat
        --disable-shared
        --enable-static
    BUILD
      $(MAKE)
    INSTALL
      $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

archiveMain()
