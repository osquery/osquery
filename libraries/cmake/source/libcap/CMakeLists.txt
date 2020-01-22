# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libcapMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/libcap")

  add_library(thirdparty_libcap
    "${library_root}/cap_alloc.c"
    "${library_root}/cap_extint.c"
    "${library_root}/cap_file.c"
    "${library_root}/cap_flag.c"
    "${library_root}/cap_proc.c"
    "${library_root}/cap_text.c"
    "${library_root}/psx.c"
    "${library_root}/libcap.h"

    "${CMAKE_CURRENT_SOURCE_DIR}/generated/cap_names.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/cap_names.list.h"
  )

  target_compile_definitions(thirdparty_libcap PRIVATE
    PIC
    _LARGEFILE64_SOURCE=1
    _FILE_OFFSET_BITS=64
  )

  target_link_libraries(thirdparty_libcap PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_libcap PRIVATE
    "${library_root}"
    "${library_root}/include"
    "${library_root}/include/uapi"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated"
  )

  target_include_directories(thirdparty_libcap SYSTEM INTERFACE
    "${library_root}/include"
    "${library_root}/include/uapi"
  )
endfunction()

libcapMain()
