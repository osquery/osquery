# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(gflagsMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")


  set(sources
    "${library_root}/src/gflags.cc"
    "${library_root}/src/gflags_reporting.cc"
    "${library_root}/src/gflags_completions.cc"
  )

  add_library(thirdparty_gflags ${sources})

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_gflags
      PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/linux/${TARGET_PROCESSOR}/private"
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/linux/${TARGET_PROCESSOR}/public"

      SYSTEM INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/linux/${TARGET_PROCESSOR}/public"
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND sources
      "${library_root}/src/windows_port.cc"
    )

    target_include_directories(thirdparty_gflags
      PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/windows/${TARGET_PROCESSOR}/private"
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/windows/${TARGET_PROCESSOR}/public"

      SYSTEM INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/windows/${TARGET_PROCESSOR}/public"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_gflags
      PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/macos/${TARGET_PROCESSOR}/private"
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/macos/${TARGET_PROCESSOR}/public"

      SYSTEM INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/macos/${TARGET_PROCESSOR}/public"
    )
  endif()

  target_compile_definitions(thirdparty_gflags
    PUBLIC
      GFLAGS_IS_A_DLL=0
      GFLAGS_DLL_DECLARE_FLAG=
      GFLAGS_DLL_DEFINE_FLAG=
  )

  target_include_directories(thirdparty_gflags
    PRIVATE
      "${library_root}/src"
      "${CMAKE_CURRENT_SOURCE_DIR}/generated"

    SYSTEM INTERFACE
      "${CMAKE_CURRENT_SOURCE_DIR}/generated"
  )

  target_link_libraries(thirdparty_gflags PRIVATE
    thirdparty_cxx_settings
  )

endfunction()

gflagsMain()
