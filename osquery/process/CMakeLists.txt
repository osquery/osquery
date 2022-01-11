# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryProcessMain)
  generateOsqueryProcess()
  generateOsqueryProcessesStats()

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()
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
    osquery_cxx_settings
    osquery_core
    osquery_utils_system_env
    thirdparty_boost
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_link_libraries(osquery_process PRIVATE
      osquery_utils_system_usersgroupshelpers
    )
  endif()

  set(public_header_files
    process.h
  )

  generateIncludeNamespace(osquery_process "osquery/process" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryProcessesStats)

  set(sources
    processes_stats.cpp
  )

  set(public_header_files
    processes_stats.h
    processes_stats_service.h
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND sources
      linux/processes_stats_service.cpp
    )
  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND sources
      darwin/processes_stats_service.cpp
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND sources
      windows/processes_stats_service.cpp
    )
  endif()

  add_osquery_library(osquery_processes_stats
    ${sources}
  )

  generateIncludeNamespace(osquery_processes_stats "osquery/process" "FILE_ONLY" ${public_header_files})

  target_link_libraries(osquery_processes_stats PRIVATE
    osquery_cxx_settings
    osquery_dispatcher
    osquery_filesystem
    osquery_process
    thirdparty_boost
  )

  if(DEFINED PLATFORM_MACOS)
    target_link_libraries(osquery_processes_stats PRIVATE
      osquery_utils_system_darwin_proc
    )
  endif()

  if(OSQUERY_BUILD_TESTS)
    add_test(NAME osquery_process_tests_processesstats-test COMMAND osquery_process_tests_processesstats-test)
  endif()
endfunction()


osqueryProcessMain()
