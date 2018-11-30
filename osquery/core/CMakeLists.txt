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

function(osquery_core_main)
  add_subdirectory("plugins")
  add_subdirectory("sql")

  generateOsqueryCore()
endfunction()

function(generateOsqueryCore)
  set(source_files
    flags.cpp
    init.cpp
    query.cpp
    system.cpp
    tables.cpp
    watcher.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/initializer.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/handle.cpp
      windows/initializer.cpp
      windows/wmi.cpp
    )
  endif()

  add_library(osquery_core EXCLUDE_FROM_ALL
    ${source_files}
  )

  set(dependencies
    osquery_headers
    osquery_config
    osquery_core_plugins
    osquery_core_sql
    osquery_filesystem
    osquery_process
    osquery_utils
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_env
    osquery_utils_system
    osquery_utils_system_time
    osquery_logger
    thirdparty_googletest
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND dependencies thirdparty_util-linux)
  endif()

  target_link_libraries(osquery_core PUBLIC
    global_cxx_settings

    ${dependencies}

    thirdparty_gflags
    thirdparty_glog
    thirdparty_openssl
  )

  set(public_header_files
    watcher.h
  )

  if(DEFINED PLATFORM_WINDOWS)
    list(APPEND public_header_files
      windows/handle.h
      windows/ntapi.h
      windows/wmi.h
    )
  endif()

  generateIncludeNamespace(osquery_core "osquery/core" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_core_main()
