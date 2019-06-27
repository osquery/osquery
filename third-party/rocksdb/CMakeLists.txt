# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(rocksdbMain)
  set(name "rocksdb")
  set(version "5.7.2")

  set(anchor_file "lib/librocksdb_lite.a")

  if(DEFINED PLATFORM_LINUX)
    set(hash "12c8abadd96ae8ac38327e8b30c195c18f30001025f400efcac82053057d9834")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "95b161e7d3def2d4f9241c57061ea1cab4f64e51f0015db490ef99eff890354d")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "2c6d47cbc32063e420965c4949832d1c5f253da282949f81d9de4d1faeb00fa8")
    set(anchor_file "lib/rocksdb.lib")
  else()
    return()
  endif()

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_bzip2)
  target_compile_definitions("thirdparty_${name}" INTERFACE -DROCKSDB_LITE=1)

endfunction()

rocksdbMain()
