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

function(osquery_process_main)
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

  add_library(osquery_process EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_process PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_utils_system_env
    thirdparty_boost
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

osquery_process_main()
