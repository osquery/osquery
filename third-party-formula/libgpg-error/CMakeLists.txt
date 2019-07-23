# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libgpgerrorMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libgpg-error")
  set(anchor_file "lib/libgpg-error.a")

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  definePrebuiltProject(${name}
    URL https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.27.tar.bz2
    SHA256 4f93aac6fecb7da2b92871bb9ee33032be6a87b174f54abf8ddf0911a22d29d2
    CONFIGURE
      ./configure
        --prefix=<INSTALL_DIR>
        --disable-shared
        --enable-static
    BUILD
      $(MAKE)
    INSTALL
      $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

libgpgerrorMain()
