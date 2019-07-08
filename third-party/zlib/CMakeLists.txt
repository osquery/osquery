# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(zlibMain)
  set(name "zlib")
  set(anchor_file "lib/libz.a")

  if(DEFINED PLATFORM_WINDOWS)
    set(anchor_file "lib/zlibstatic.lib")
  endif()

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  if (DEFINED PLATFORM_WINDOWS)
    set(configure_options
      -DCMAKE_C_FLAGS_RELEASE:STRING=/MT\ /O2\ /Ob2\ /DNDEBUG
    )
  endif()

  definePrebuiltProject(${name}
    URL https://downloads.sourceforge.net/project/libpng/zlib/1.2.11/zlib-1.2.11.tar.gz
    SHA256 c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1
    DEPENDS ${dependencies}
    CONFIGURE
      cmake
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DBUILD_SHARED_LIBS=OFF
        ${configure_options}
        <SOURCE_DIR>
    BUILD
      cmake --build . --config Release
    INSTALL
      cmake --build . --config Release --target install
  )
endfunction()

zlibMain()
