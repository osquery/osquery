# Copyright (c) 2018-present, Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13.1)

function(osquery_profiler_main)
  generateOsqueryProfiler()
endfunction()

function(generateOsqueryProfiler)
  if(DEFINED PLATFORM_POSIX)
    set(source_files
      posix/profiler.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    set(source_files
      windows/profiler.cpp
    )
  endif()

  add_library(osquery_profiler EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_profiler PUBLIC
    global_cxx_settings
    osquery_core
  )

  set(public_header_files
    profiler.h
  )

  generateIncludeNamespace(osquery_profiler "osquery/profiler" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_profiler_main()
