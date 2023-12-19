# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

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
    PIC
  )

  if(DEFINED PLATFORM_POSIX)
    target_compile_definitions(thirdparty_zlib PRIVATE
      HAVE_HIDDEN
      HAVE_UNISTD_H
      HAVE_STDARG_H
    )
  endif()

  if(DEFINED PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_zlib PRIVATE
      NO_FSEEKO
      _CRT_NONSTDC_NO_DEPRECATE
      _CRT_SECURE_NO_DEPRECATE
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    target_compile_definitions(thirdparty_zlib PRIVATE
      _LARGEFILE64_SOURCE=1
    )
  endif()

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
