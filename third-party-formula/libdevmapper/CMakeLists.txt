# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libdevmapperMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libdevmapper")
  set(anchor_file "lib/liblvm2app.a")

  set(additional_libraries
    lib/liblvm-internal.a
    lib/libdevmapper.a
    lib/libdaemonclient.a
  )

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}" ${additional_libraries})

  set(dependencies util-linux)
  definePrebuiltProject(${name}
    URL https://www.mirrorservice.org/sites/sourceware.org/pub/lvm2/old/LVM2.2.02.173.tgz
    SHA256 ceb9168c7e009ef487f96a1fe969b23cbb07d920ffb71769affdbdf30fea8d64
    DEPENDS ${dependencies}
    CONFIGURE
      export VALGRIND_CFLAGS=-fPIC\ -I/usr/include/valgrind &&
      ./configure
        --prefix=<INSTALL_DIR>
        --with-lvm1=none
        --disable-selinux
        --disable-readline
        --enable-static_link
    BUILD
      $(MAKE) libdm.device-mapper &&
      cd <SOURCE_DIR>/libdm && $(MAKE) install &&
      cd <SOURCE_DIR>/lib && $(MAKE) &&
      cd <SOURCE_DIR>/libdaemon && $(MAKE) &&
      cd <SOURCE_DIR>/liblvm && $(MAKE) install
    INSTALL
      cp <SOURCE_DIR>/lib/liblvm-internal.a <INSTALL_DIR>/lib &&
      cp <SOURCE_DIR>/libdaemon/client/libdaemonclient.a <INSTALL_DIR>/lib
    BUILD_IN_SOURCE ON
  )
endfunction()

libdevmapperMain()
