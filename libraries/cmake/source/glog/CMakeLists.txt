# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(googleLogMain)

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  set(sources
    "${library_root}/src/demangle.cc"
    "${library_root}/src/logging.cc"
    "${library_root}/src/raw_logging.cc"
    "${library_root}/src/symbolize.cc"
    "${library_root}/src/utilities.cc"
    "${library_root}/src/vlog_is_on.cc"
    "${library_root}/src/signalhandler.cc"
  )

  configure_file("${library_root}/src/glog/log_severity.h" "${CMAKE_CURRENT_BINARY_DIR}/glog/log_severity.h" COPYONLY)

  if(DEFINED PLATFORM_WINDOWS)
    list(APPEND sources
      "${library_root}/src/windows/port.cc"
    )
  endif()

  add_library(thirdparty_glog ${sources})

  if(DEFINED PLATFORM_POSIX)
    target_compile_options(thirdparty_glog PUBLIC
      -Wno-unnamed-type-template-args
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_glog PUBLIC
      GLOG_NO_ABBREVIATED_SEVERITIES
      NOMINMAX # Needed to avoid collisions with the macro min()
    )
  endif()

  target_compile_definitions(thirdparty_glog PUBLIC
    GOOGLE_GLOG_DLL_DECL=
    GLOG_NO_SYMBOLIZE_DETECTION
    GLOG_CUSTOM_PREFIX_SUPPORT
  )

  target_link_libraries(thirdparty_glog
    PRIVATE
      thirdparty_cxx_settings
    PUBLIC
      thirdparty_gflags
  )

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_glog
      PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/linux/${TARGET_PROCESSOR}/private"
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/linux/${TARGET_PROCESSOR}/public"

      SYSTEM INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/linux/${TARGET_PROCESSOR}/public"
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    target_include_directories(thirdparty_glog
      PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/windows/${TARGET_PROCESSOR}/private"
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/windows/${TARGET_PROCESSOR}/public"
        "${library_root}/src/windows"

      SYSTEM INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/windows/${TARGET_PROCESSOR}/public"
        "${library_root}/src/windows"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_glog
      PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/macos/${TARGET_PROCESSOR}/private"
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/macos/${TARGET_PROCESSOR}/public"

      SYSTEM INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/generated/macos/${TARGET_PROCESSOR}/public"
    )
  endif()

  target_include_directories(thirdparty_glog
    PRIVATE
      "${library_root}/src"
      "${CMAKE_CURRENT_BINARY_DIR}"

    SYSTEM INTERFACE
      "${CMAKE_CURRENT_BINARY_DIR}"
  )
endfunction()

googleLogMain()
