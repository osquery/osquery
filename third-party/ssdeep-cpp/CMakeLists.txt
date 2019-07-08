# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(ssdeepCppMain)
  set(name "ssdeep-cpp")

  if(DEFINED PLATFORM_WINDOWS)
    add_osquery_library(thirdparty_ssdeep-cpp INTERFACE)
    return()
  endif()

  set(anchor_file "lib/libfuzzy.a")

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  definePrebuiltProject(${name}
    URL https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz
    SHA256 ff2eabc78106f009b4fb2def2d76fb0ca9e12acf624cbbfad9b3eb390d931313
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

ssdeepCppMain()
