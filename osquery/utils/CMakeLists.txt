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

function(osquery_utils_main)
  add_subdirectory("aws")
  add_subdirectory("system")
  add_subdirectory("status")
  add_subdirectory("json")
  add_subdirectory("macros")
  add_subdirectory("config")
  add_subdirectory("info")
  add_subdirectory("error")
  add_subdirectory("debug")
  add_subdirectory("expected")
  add_subdirectory("conversions")

  generateOsqueryUtils()
endfunction()

function(generateOsqueryUtils)
  set(source_files
    base64.cpp
    chars.cpp
    only_movable.cpp
  )

  if(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      darwin/plist.mm
    )
  endif()

  add_library(osquery_utils EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_utils PUBLIC
    global_cxx_settings
    thirdparty_glog
    osquery_logger
    osquery_utils_config
    osquery_utils_conversions
    osquery_utils_expected
    osquery_utils_info
    osquery_utils_status
  )

  set(public_header_files
    base64.h
    chars.h
    map_take.h
    mutex.h
    only_movable.h
    scope_guard.h
  )

  generateIncludeNamespace(osquery_utils "osquery/utils" "FILE_ONLY" ${public_header_files})

  if(DEFINED PLATFORM_MACOS)
    set(platform_public_header_files
      darwin/plist.h
    )

    generateIncludeNamespace(osquery_utils "osquery/utils" "FULL_PATH" ${platform_public_header_files})
  endif()
endfunction()

osquery_utils_main()
