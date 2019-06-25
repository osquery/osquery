# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

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
    global_cxx_settings
    osquery_core
  )

  set(public_header_files
    code_profiler.h
  )

  generateIncludeNamespace(osquery_profiler "osquery/profiler" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryProfilerMain()
