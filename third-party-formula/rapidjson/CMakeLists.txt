# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(rapidjsonMain)
  set(name "rapidjson")
  set(anchor_file "include/rapidjson/rapidjson.h")

  importThirdPartyHeaderOnlyLibrary("PREBUILT" "${name}" "${anchor_file}" "include")

  set(additional_flags "$ENV{CXXFLAGS}")
  if(NOT DEFINED PLATFORM_WINDOWS)
    set(additional_flags "-Wno-unknown-warning-option -Wno-extra-semi-stmt -Wno-zero-as-null-pointer-constant -Wno-shadow ${additional_flags}")
  endif()

  definePrebuiltProject(${name}
    URL https://github.com/miloyip/rapidjson/archive/v1.1.0.tar.gz
    SHA256 bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e
    PATCHES librapidjson-1.1.0-1.patch
    CONFIGURE
      cmake
        -DCMAKE_CXX_FLAGS_RELEASE=${additional_flags}
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DRAPIDJSON_BUILD_DOC=OFF
        -DCMAKE_BUILD_TYPE=Release
      <SOURCE_DIR>
    BUILD
      cmake --build . --config Release
    INSTALL
      cmake --build . --config Release --target install
  )
endfunction()

rapidjsonMain()
