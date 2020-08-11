# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryProfilerMain)
  generateOsqueryProfiler()
endfunction()

function(generateOsqueryProfiler)
  if(DEFINED PLATFORM_POSIX)
    set(source_files
      posix/code_profiler.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    set(source_files
      windows/code_profiler.cpp
    )
  endif()

  add_osquery_library(osquery_profiler EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_profiler PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_numericmonitoring
  )

  set(public_header_files
    code_profiler.h
  )

  generateIncludeNamespace(osquery_profiler "osquery/profiler" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryProfilerMain()
