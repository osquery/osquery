# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(poptMain)
  set(name "popt")

  if(DEFINED PLATFORM_WINDOWS)
    return()
  endif()

  set(anchor_file "lib/libpopt.a")

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  definePrebuiltProject(${name}
    URL https://fossies.org/linux/misc/popt-1.16.tar.gz
    SHA256 e728ed296fe9f069a0e005003c3d6b2dde3d9cad453422a10d6558616d304cc8
    CONFIGURE
      ./configure
        --prefix=<INSTALL_DIR>
        --disable-debug
        --disable-shared
        --enable-static
    BUILD
      $(MAKE)
    INSTALL
      $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

poptMain()
