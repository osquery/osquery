# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(lzmaMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "lzma")

  set(anchor_file lib/liblzma.a)

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  definePrebuiltProject(${name}
    URL https://tukaani.org/xz/xz-5.2.4.tar.gz
    SHA256 b512f3b726d3b37b6dc4c8570e137b9311e7552e8ccbab4d39d47ce5f4177145
    CONFIGURE
      ./autogen.sh &&
      ./configure --prefix=<INSTALL_DIR>
        --disable-shared
        --enable-static
    BUILD
      $(MAKE)
    INSTALL
      $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

lzmaMain()
