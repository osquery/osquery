# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libmagicMain)
  set(name "libmagic")

  if(DEFINED PLATFORM_WINDOWS)
    add_osquery_library(thirdparty_libmagic INTERFACE)
    return()
  endif()

  set(anchor_file "lib/libmagic.a")

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_zlib)

  set(dependencies zlib)
  definePrebuiltProject(${name}
    URL https://distfiles.macports.org/file/file-5.32.tar.gz
    SHA256 8639dc4d1b21e232285cd483604afc4a6ee810710e00e579dbe9591681722b50
    DEPENDS ${dependencies}
    CONFIGURE
      ./configure
        --prefix=<INSTALL_DIR>
        --enable-fsect-man5
        --enable-static
        --disable-shared
    BUILD
      $(MAKE)
    INSTALL
      $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

libmagicMain()
