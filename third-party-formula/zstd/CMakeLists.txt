# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(zstdMain)
  set(name "zstd")
  set(anchor_file "lib/libzstd.a")

  if(DEFINED PLATFORM_WINDOWS)
    set(anchor_file "lib/zstd_static.lib")
  endif()

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  definePrebuiltProject(${name}
    URL https://github.com/facebook/zstd/releases/download/v1.4.0/zstd-1.4.0.tar.gz
    SHA256 7f323f0e0c18488748f3d9b2d4353f00e904ea2ccd0372ea04d7f77aa1156557
    CONFIGURE
      cmake
        -DZSTD_USE_STATIC_RUNTIME=ON
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DCMAKE_BUILD_TYPE=Release
        -DBUILD_SHARED_LIBS=OFF
        -DZSTD_BUILD_SHARED=OFF
        <SOURCE_DIR>/build/cmake
    BUILD
      cmake --build . --config Release
    INSTALL
      cmake --build . --config Release --target install
  )
endfunction()

zstdMain()
