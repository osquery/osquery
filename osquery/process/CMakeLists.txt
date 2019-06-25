# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryProcessMain)
  generateOsqueryProcess()
endfunction()

function(generateOsqueryProcess)
  if(DEFINED PLATFORM_POSIX)
    set(source_files
      posix/process.cpp
      posix/process_ops.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    set(source_files
      windows/process.cpp
      windows/process_ops.cpp
    )
  endif()

  add_osquery_library(osquery_process EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_process PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_utils_system_env
    thirdparty_boost
    thirdparty_glibc_dl
  )

  set(public_header_files
    process.h
  )

  generateIncludeNamespace(osquery_process "osquery/process" "FILE_ONLY" ${public_header_files})

  if(DEFINED PLATFORM_WINDOWS)
    set(platform_public_header_files
      windows/process_ops.h
    )

    generateIncludeNamespace(osquery_process "osquery/process" "FULL_PATH" ${platform_public_header_files})
  endif()
endfunction()

osqueryProcessMain()
