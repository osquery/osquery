# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(sleuthkitMain)
  set(name "sleuthkit")

  if(DEFINED PLATFORM_WINDOWS)
    return()
  endif()

  set(anchor_file "lib/libtsk.a")

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  definePrebuiltProject(${name}
    URL https://github.com/sleuthkit/sleuthkit/archive/sleuthkit-4.6.1.tar.gz
    SHA256 bb2c936dbc88820fc4a875bc9b610f56c6a4a61b7bc8625f86be2549a948a7a9
    CONFIGURE
      ./bootstrap &&
      ./configure
        --prefix=<INSTALL_DIR>
        --disable-java
        --disable-shared
        --enable-static
    BUILD
      $(MAKE)
    INSTALL
      $(MAKE) install
    BUILD_IN_SOURCE ON
  )

  add_dependencies("thirdparty_build_${name}" "thirdparty_sqlite")
endfunction()

sleuthkitMain()
