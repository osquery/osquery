# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(yaraMain)
  if(DEFINED PLATFORM_WINDOWS)
    return()
  endif()

  set(name "yara")
  set(anchor_file "lib/libyara.a")

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_openssl)

  set(dependencies openssl)
  definePrebuiltProject(${name}
    URL https://github.com/VirusTotal/yara/archive/v3.7.1.tar.gz
    SHA256 df077a29b0fffbf4e7c575f838a440f42d09b215fcb3971e6fb6360318a64892
    DEPENDS ${dependencies}
    CONFIGURE
      ./bootstrap.sh &&
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

yaraMain()
