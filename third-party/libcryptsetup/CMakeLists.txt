# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libcryptsetupMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libcryptsetup")
  set(anchor_file "lib/libcryptsetup.a")

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_libgcrypt)

  set(dependencies util-linux libdevmapper popt libgcrypt)
  definePrebuiltProject(${name}
    URL https://gitlab.com/cryptsetup/cryptsetup/repository/v1_7_5/archive.tar.gz
    SHA256 6dead2f1420ab1c84a7e82f0ee197861f4a52e4c3284a0bfef824a90c392e077
    DEPENDS ${dependencies}
    CONFIGURE
    ./autogen.sh
      --prefix=<INSTALL_DIR>
      --with-libgcrypt-prefix=<INSTALL_DIR>
      --disable-selinux
      --disable-udev
      --disable-veritysetup
      --disable-nls
      --disable-kernel_crypto
      --disable-shared
      --enable-static
    BUILD
      cd lib && $(MAKE)
    INSTALL
      cd lib && $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

libcryptsetupMain()
