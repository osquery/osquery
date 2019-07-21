# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(linenoisengMain)
  set(name "linenoise-ng")

  set(anchor_file "lib/liblinenoise.a")

  if(DEFINED PLATFORM_WINDOWS)
    set(anchor_file "lib/linenoise.lib")
  endif()

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  definePrebuiltProject(${name}
    URL https://github.com/arangodb/linenoise-ng/archive/master.zip
    SHA256 35f8fa471328dd534da111f46c1814fb7efdf0feafb1b71c5a6b4b98d5fd67e8
    CONFIGURE
      cmake
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DCMAKE_BUILD_TYPE=Release
        -DBUILD_SHARED_LIBS=OFF
        <SOURCE_DIR>
    BUILD
      cmake --build . --config Release
    INSTALL
      cmake --build . --config Release --target install
  )
endfunction()

linenoisengMain()
