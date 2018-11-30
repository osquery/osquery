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

function(osquery_utils_status_main)
  generateOsqueryUtilsStatus()
endfunction()

function(generateOsqueryUtilsStatus)
  add_library(osquery_utils_status EXCLUDE_FROM_ALL
    status.cpp
  )

  target_link_libraries(osquery_utils_status PUBLIC
    global_cxx_settings
    osquery_utils_error
    osquery_utils_expected
  )

  set(public_header_files
    status.h
  )

  generateIncludeNamespace(osquery_utils_status "osquery/utils" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_utils_status_main()
