# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libcapMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/libcap")

  add_library(thirdparty_libcap
    "${library_root}/cap_alloc.c"
    "${library_root}/cap_extint.c"
    "${library_root}/cap_file.c"
    "${library_root}/cap_flag.c"
    "${library_root}/cap_proc.c"
    "${library_root}/cap_text.c"

    "${CMAKE_CURRENT_SOURCE_DIR}/generated/cap_names.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/cap_names.list.h"
  )

  target_compile_definitions(thirdparty_libcap PRIVATE
    linux
    _LARGEFILE64_SOURCE
    _FILE_OFFSET_BITS=64
  )

  target_link_libraries(thirdparty_libcap PRIVATE
    thirdparty_c_settings
  )

  set_target_properties (thirdparty_libcap PROPERTIES
    POSITION_INDEPENDENT_CODE
      ON
  )

  target_include_directories(thirdparty_libcap PRIVATE
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
