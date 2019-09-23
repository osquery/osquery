# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libmagicMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_libmagic
    "${library_root}/src/cdf_time.c"
    "${library_root}/src/is_tar.c"
    "${library_root}/src/encoding.c"
    "${library_root}/src/strlcpy.c"
    "${library_root}/src/readcdf.c"
    "${library_root}/src/der.c"
    "${library_root}/src/readelf.c"
    "${library_root}/src/fmtcheck.c"
    "${library_root}/src/fsmagic.c"
    "${library_root}/src/apprentice.c"
    "${library_root}/src/cdf.c"
    "${library_root}/src/print.c"
    "${library_root}/src/compress.c"
    "${library_root}/src/magic.c"
    "${library_root}/src/softmagic.c"
    "${library_root}/src/strlcat.c"
    "${library_root}/src/apptype.c"
    "${library_root}/src/funcs.c"
    "${library_root}/src/ascmagic.c"
  )

  target_compile_definitions(thirdparty_libmagic PRIVATE
    HAVE_CONFIG_H
    MAGIC=\"/usr/local/share/misc/magic\"
  )

  target_compile_options(thirdparty_libmagic PRIVATE
    -include config.h
  )

  target_link_libraries(thirdparty_libmagic PUBLIC
    thirdparty_zlib
  )

  target_link_libraries(thirdparty_libmagic PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_libmagic PRIVATE
    "${library_root}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
  )

  target_include_directories(thirdparty_libmagic SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )
endfunction()

libmagicMain()
