# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(utillinuxMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "util-linux")
  set(anchor_file "lib/libuuid.a")

  set(additional_libraries
    lib/libblkid.a
  )

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}" ${additional_libraries})

  set(dependencies ncurses)
  definePrebuiltProject(${name}
    URL https://www.kernel.org/pub/linux/utils/util-linux/v2.27/util-linux-2.27.1.tar.xz
    SHA256 0a818fcdede99aec43ffe6ca5b5388bff80d162f2f7bd4541dca94fecb87a290
    DEPENDS ${dependencies}
    CONFIGURE
      export NCURSES_CFLAGS=-I${THIRD_PARTY_PREFIX}/include/ncurses &&
      ./autogen.sh &&
      ./configure
        --prefix=<INSTALL_DIR>
        --disable-all-programs
        --disable-bash-completion
        --without-ncurses
        --enable-libuuid
        --enable-libblkid
        --disable-use-tty-group
        --disable-kill
        --disable-shared
        --without-readline
        --enable-static
    BUILD
      $(MAKE)
    INSTALL
      $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

utillinuxMain()
