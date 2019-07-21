# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libdpkgMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libdpkg")
  set(anchor_file "lib/libdpkg.a")

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_zlib)

  set(dependencies zlib bzip2 lzma)
  definePrebuiltProject(${name}
    URL https://launchpad.net/debian/+archive/primary/+sourcefiles/dpkg/1.19.0.5/dpkg_1.19.0.5.tar.xz
    SHA256 818046927a7f77c1bcbbad7d8dbc04cdf0f3e6ec4e1a4f9d313378ecc69d85b5
    DEPENDS ${dependencies}
    CONFIGURE
      ./configure
        --prefix=<INSTALL_DIR>
        --disable-dselect
        --disable-start-stop-daemon
    BUILD
      cd lib && $(MAKE)
    INSTALL
      cd lib && $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

libdpkgMain()
