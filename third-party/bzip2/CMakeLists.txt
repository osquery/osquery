# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(bzip2Main)
  set(name "bzip2")
  set(anchor_file "lib/libbz2.a")

  if(DEFINED PLATFORM_MACOS)
    add_osquery_library(thirdparty_bzip2 INTERFACE)
    target_link_libraries(thirdparty_bzip2 INTERFACE "bz2")
    return()
  elseif(DEFINED PLATFORM_WINDOWS)
    add_osquery_library(thirdparty_bzip2 INTERFACE)
    return()
  endif()

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  definePrebuiltProject(${name}
    URL https://src.fedoraproject.org/lookaside/pkgs/bzip2/bzip2-1.0.6.tar.gz/00b516f4704d4a7cb50a1d97e6e8e15b/bzip2-1.0.6.tar.gz
    SHA256 a2848f34fcd5d6cf47def00461fcb528a0484d8edef8208d6d2e2909dc61d9cd
    DEPENDS ${dependencies}
    CONFIGURE
      ${REPLACE_CMD} "CFLAGS=" "CFLAGS=$ENV{CFLAGS} " Makefile &&
      ${REPLACE_CMD} "CC=gcc" "CC=$ENV{CC}" Makefile
    BUILD true
    INSTALL
      $(MAKE) install PREFIX=<INSTALL_DIR>
    BUILD_IN_SOURCE ON
  )
endfunction()

bzip2Main()
