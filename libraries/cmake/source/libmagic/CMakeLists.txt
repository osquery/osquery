# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libmagicMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  set(source_files
    "${library_root}/src/buffer.c"
    "${library_root}/src/magic.c"
    "${library_root}/src/apprentice.c"
    "${library_root}/src/softmagic.c"
    "${library_root}/src/ascmagic.c"
    "${library_root}/src/encoding.c"
    "${library_root}/src/compress.c"
    "${library_root}/src/is_csv.c"
    "${library_root}/src/is_json.c"
    "${library_root}/src/is_tar.c"
    "${library_root}/src/readelf.c"
    "${library_root}/src/print.c"
    "${library_root}/src/fsmagic.c"
    "${library_root}/src/funcs.c"
    "${library_root}/src/apptype.c"
    "${library_root}/src/der.c"
    "${library_root}/src/cdf.c"
    "${library_root}/src/cdf_time.c"
    "${library_root}/src/readcdf.c"
  )

  set(compile_definition_list
    HAVE_CONFIG_H
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND compile_definition_list
      MAGIC=\"/usr/local/share/misc/magic\"
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      "${library_root}/src/strlcat.c"
      "${library_root}/src/strlcpy.c"
      "${library_root}/src/fmtcheck.c"
    )
  endif()

  add_library(thirdparty_libmagic ${source_files})
  target_compile_definitions(thirdparty_libmagic PRIVATE
    ${compile_definition_list}
    -Dbuffer_init=libmagic_buffer_init
  )

  target_link_libraries(thirdparty_libmagic PUBLIC
    thirdparty_zlib
    thirdparty_lzma
  )

  target_link_libraries(thirdparty_libmagic PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_libmagic PRIVATE
    "${library_root}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_libmagic PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux/${TARGET_PROCESSOR}"
    )

  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_libmagic PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos/${TARGET_PROCESSOR}"
    )
  endif()

  target_include_directories(thirdparty_libmagic SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )
endfunction()

libmagicMain()
