# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(bzip2Main)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_bzip2
    "${library_root}/randtable.c"
    "${library_root}/decompress.c"
    "${library_root}/bzip2recover.c"
    "${library_root}/unzcrash.c"
    "${library_root}/bzip2.c"
    "${library_root}/dlltest.c"
    "${library_root}/bzlib.c"
    "${library_root}/blocksort.c"
    "${library_root}/compress.c"
    "${library_root}/huffman.c"
    "${library_root}/mk251.c"
    "${library_root}/crctable.c"
    "${library_root}/spewG.c"
  )

  # todo(alessandro): macOS and Windows support
  target_compile_definitions(thirdparty_bzip2 PRIVATE
    _FILE_OFFSET_BITS=64
  )

  target_link_libraries(thirdparty_bzip2 PUBLIC
    global_c_settings
    thirdparty_silence_warnings
  )

  target_include_directories(thirdparty_bzip2 SYSTEM PUBLIC
    "${library_root}"
  )
endfunction()

bzip2Main()
