# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(lldpdMain)
  set(name "lldpd")

  if(DEFINED PLATFORM_WINDOWS)
    return()
  endif()

  set(anchor_file "lib/liblldpctl.a")

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  set(dependencies zlib)
  if(DEFINED PLATFORM_LINUX)
    list(APPEND dependencies bzip2)
  endif()

  definePrebuiltProject(${name}
    URL https://media.luffy.cx/files/lldpd/lldpd-0.9.6.tar.gz
    SHA256 e74e2dd7e2a233ca1ff385c925ddae2a916d302819d1433741407d2f8fb0ddd8
    DEPENDS ${dependencies}
    CONFIGURE
      ./autogen.sh &&
      ./configure
        --prefix=<INSTALL_DIR>
        --with-systemdsystemunitdir=<INSTALL_DIR>/share
        --with-sysusersdir=<INSTALL_DIR>/share
        --with-privsep-chroot=/var/empty
        --with-privsep-user=nobody
        --with-privsep-group=nogroup
        --with-launchddaemonsdir=no
        --with-xml=no
        --with-json=no
        --with-readline=no
        --disable-shared
        --enable-static
    BUILD
      $(MAKE)
    INSTALL
      $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

lldpdMain()
