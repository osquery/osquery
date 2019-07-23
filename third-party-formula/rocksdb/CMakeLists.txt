# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(rocksdbMain)
  set(name "rocksdb")

  set(anchor_file "lib/librocksdb_lite.a")

  if(DEFINED PLATFORM_WINDOWS)
    set(anchor_file "lib/rocksdb_lite.lib")
  endif()

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_bzip2)
  target_compile_definitions("thirdparty_${name}" INTERFACE -DROCKSDB_LITE=1)

  if(DEFINED PLATFORM_WINDOWS)
    set(lib_name rocksdb.lib)
    set(lib_target rocksdb_lite.lib)
    set(configure_options
      -DROCKSDB_INSTALL_ON_WINDOWS=ON
      -DCMAKE_CXX_FLAGS_RELEASE:STRING=/MT\ /O2\ /Ob2\ /DNDEBUG
    )
  else()
    set(lib_name librocksdb.a)
    set(lib_target librocksdb_lite.a)
  endif()

  definePrebuiltProject(${name}
    URL https://github.com/facebook/rocksdb/archive/v6.1.2.tar.gz
    SHA256 df93f3b66caa1cbe1c2862c99c33e18a5c5b24a64fb51dfe8ef805e3c9fd1cad
    CONFIGURE
      cmake
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DROCKSDB_LITE=ON
        -DWITH_GFLAGS=OFF
        -DWITH_RUNTIME_DEBUG=OFF
        -DWITH_TESTS=OFF
        -DWITH_TOOLS=OFF
        -DUSE_RTTI=OFF
        -DPORTABLE=ON
        -DFAIL_ON_WARNINGS=OFF
        -DWITH_MD_LIBRARY=OFF
        ${configure_options}
        <SOURCE_DIR>
    BUILD
      cmake --build . --config Release
    INSTALL
      cmake --build . --config Release --target install &&
      mv <INSTALL_DIR>/lib/${lib_name} <INSTALL_DIR>/lib/${lib_target}
  )
endfunction()

rocksdbMain()
