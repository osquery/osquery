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

function(osquery_extensions_main)
  add_subdirectory("thrift")
  generateOsqueryExtensions()
endfunction()

function(generateOsqueryExtensions)
  add_library(osquery_extensions EXCLUDE_FROM_ALL
    extensions.cpp
    impl_thrift.cpp
    interface.cpp
  )

  target_link_libraries(osquery_extensions PUBLIC
    global_cxx_settings
    osquery_core
    osquery_extensions_thrift_osquery-cpp2
    osquery_process
    osquery_utils
    osquery_utils_conversions
  )

  if(DEFINED PLATFORM_FREEBSD)
    target_link_libraries(osquery_extensions PUBLIC thirdparty_thrift)
  endif()

  set(public_header_files
    interface.h
  )

  generateIncludeNamespace(osquery_extensions "osquery/extensions" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_extensions_main()
