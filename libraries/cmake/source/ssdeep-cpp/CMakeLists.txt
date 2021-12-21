# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(ssdeepMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_ssdeep
    "${library_root}/fuzzy.c"
    "${library_root}/edit_dist.c"
  )

  target_compile_definitions(thirdparty_ssdeep PRIVATE
    HAVE_CONFIG_H
  )

  target_link_libraries(thirdparty_ssdeep PRIVATE
    thirdparty_c_settings
  )

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_ssdeep PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/linux"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_ssdeep PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/macos"
    )
  endif()

  target_include_directories(thirdparty_ssdeep PRIVATE
    "${library_root}"
  )

  target_include_directories(thirdparty_ssdeep SYSTEM INTERFACE
    "${library_root}"
  )
endfunction()

ssdeepMain()
