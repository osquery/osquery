# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryExperimentalTracingMain)
  add_subdirectory("linux")

  generateOsqueryExperimentalTracingSyscallstracing()
endfunction()

function(generateOsqueryExperimentalTracingSyscallstracing)

  set(source_files
    syscalls_tracing.cpp
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      syscalls_tracing_impl.cpp
    )
  endif()

  add_osquery_library(osquery_experimental_tracing_syscallstracing EXCLUDE_FROM_ALL ${source_files})

  target_link_libraries(osquery_experimental_tracing_syscallstracing PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_dispatcher
    osquery_experimental_tracing_linux_probesevents
    osquery_experimental_eventsstream
    osquery_utils_caches_lru
    osquery_utils_conversions
    osquery_utils_json
    osquery_utils_system_linux_proc
    osquery_utils_system_time
  )

  set(public_header_files
    syscalls_tracing.h
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND public_header_files
      syscalls_tracing_impl.h
    )
  endif()

  generateIncludeNamespace(osquery_experimental_tracing_syscallstracing "osquery/experimental/tracing" "FILE_ONLY" ${public_header_files})

endfunction()

osqueryExperimentalTracingMain()
