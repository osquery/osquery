# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(zlibMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_zlib
    "${library_root}/adler32.c"
    "${library_root}/compress.c"
    "${library_root}/crc32.c"
    "${library_root}/deflate.c"
    "${library_root}/gzclose.c"
    "${library_root}/gzlib.c"
    "${library_root}/gzread.c"
    "${library_root}/gzwrite.c"
    "${library_root}/infback.c"
    "${library_root}/inffast.c"
    "${library_root}/inflate.c"
    "${library_root}/inftrees.c"
    "${library_root}/trees.c"
    "${library_root}/uncompr.c"
    "${library_root}/zutil.c"
  )

  target_compile_definitions(thirdparty_zlib PRIVATE
    _LARGEFILE64_SOURCE=1
    HAVE_HIDDEN
    PIC
    HAVE_UNISTD_H
    HAVE_STDARG_H
  )

  target_link_libraries(thirdparty_zlib PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_zlib PRIVATE
    "${library_root}"
  )

  target_include_directories(thirdparty_zlib SYSTEM INTERFACE
    "${library_root}"
  )
endfunction()

zlibMain()
