# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libiptablesMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libiptables")
  set(anchor_file "lib/libip4tc.a")

  set(additional_libraries
    lib/libip6tc.a
    lib/libiptc.a
  )

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}" ${additional_libraries})

  definePrebuiltProject(${name}
    URL https://ftp.osuosl.org/pub/blfs/conglomeration/iptables/iptables-1.8.3.tar.bz2
    SHA256 a23cac034181206b4545f4e7e730e76e08b5f3dd78771ba9645a6756de9cdd80
    DEPENDS ${dependencies}
    CONFIGURE
      ./configure
        --prefix=<INSTALL_DIR>
        --disable-nftables
        --disable-shared
    BUILD
      cd libiptc && $(MAKE)
    INSTALL
      cd <SOURCE_DIR>/libiptc && $(MAKE) install &&
      cd <SOURCE_DIR>/include && $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

libiptablesMain()
