# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(glogMain)
  set(name "glog")
  set(anchor_file "lib/libglog.a")

  if(DEFINED PLATFORM_WINDOWS)
    set(anchor_file "lib/glog.lib")
  endif()

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_gflags)

  if(DEFINED PLATFORM_WINDOWS)
    set(configure_options
      -DCMAKE_CXX_FLAGS_RELEASE:STRING=/MT\ /O2\ /Ob2\ /DNDEBUG
    )
  endif()

  set(dependencies gflags)
  definePrebuiltProject(${name}
    URL https://github.com/google/glog/archive/v0.3.5.tar.gz
    SHA256 7580e408a2c0b5a89ca214739978ce6ff480b5e7d8d7698a2aa92fadc484d1e0
    DEPENDS ${dependencies}
    CONFIGURE
      cmake
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DBUILD_SHARED_LIBS=OFF
        -DBUILD_TESTING=OFF
        ${configure_options}
        <SOURCE_DIR>
    BUILD
      cmake --build . --config Release
    INSTALL
      cmake --build . --config Release --target install
  )
endfunction()

glogMain()
