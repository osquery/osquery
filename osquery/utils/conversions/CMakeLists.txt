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

function(osquery_utils_conversions_main)
  generateOsqueryUtilsConversions()
endfunction()

function(generateOsqueryUtilsConversions)
  set(source_files
    split.cpp
    tryto.cpp
  )

  if(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      darwin/cfdata.cpp
      darwin/cfnumber.cpp
      darwin/cfstring.cpp
      darwin/cftime.cpp
      darwin/iokit.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/strings.cpp
    )
  endif()

  add_library(osquery_utils_conversions EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_utils_conversions PUBLIC
    global_cxx_settings
    osquery_utils_expected
    thirdparty_boost
    thirdparty_glog
  )

  set(public_header_files
    join.h
    split.h
    tryto.h
  )

  generateIncludeNamespace(osquery_utils_conversions "osquery/utils/conversions" "FILE_ONLY" ${public_header_files})

  if(DEFINED PLATFORM_MACOS)
    set(platform_public_header_files
      darwin/cfdata.h
      darwin/cfnumber.h
      darwin/cfstring.h
      darwin/cftime.h
      darwin/iokit.h
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    set(platform_public_header_files
      windows/strings.h
    )
  endif()

  list(LENGTH platform_public_header_files platform_public_header_files_size)
  if(${platform_public_header_files_size} GREATER 0)
    generateIncludeNamespace(osquery_utils_conversions "osquery/utils/conversions" "FULL_PATH" ${platform_public_header_files})
  endif()
endfunction()

osquery_utils_conversions_main()
