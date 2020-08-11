# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(bzip2Main)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_bzip2
    "${library_root}/randtable.c"
    "${library_root}/decompress.c"
    "${library_root}/bzlib.c"
    "${library_root}/blocksort.c"
    "${library_root}/compress.c"
    "${library_root}/huffman.c"
    "${library_root}/crctable.c"
  )

  target_compile_definitions(thirdparty_bzip2 PRIVATE
    _FILE_OFFSET_BITS=64
  )

  target_link_libraries(thirdparty_bzip2 PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_bzip2 PRIVATE
    "${library_root}"
  )

  target_include_directories(thirdparty_bzip2 SYSTEM INTERFACE
    "${library_root}"
  )
endfunction()

bzip2Main()
