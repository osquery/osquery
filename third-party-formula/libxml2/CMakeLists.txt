# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libxml2Main)
  set(name "libxml2")

  if(DEFINED PLATFORM_WINDOWS)
    add_osquery_library(thirdparty_libxml2 INTERFACE)
    return()
  endif()

  set(anchor_file "lib/libxml2.a")

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_zlib)

  set(dependencies zlib)
  definePrebuiltProject(${name}
    URL http://xmlsoft.org/sources/libxml2-2.9.7.tar.gz
    SHA256 f63c5e7d30362ed28b38bfa1ac6313f9a80230720b7fb6c80575eeab3ff5900c
    DEPENDS ${dependencies}
    CONFIGURE
      ./configure
        --prefix=<INSTALL_DIR>
        --without-python
        --without-lzma
        --with-zlib=<INSTALL_DIR>
        --disable-shared
        --enable-static
    BUILD
      $(MAKE)
    INSTALL
      $(MAKE) install &&
      ln -sf libxml2/libxml <INSTALL_DIR>/include
    BUILD_IN_SOURCE ON
  )
endfunction()

libxml2Main()
