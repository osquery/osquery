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

function(osquery_utils_expected_main)
  generateOsqueryUtilsExpected()
endfunction()

function(generateOsqueryUtilsExpected)
  add_library(osquery_utils_expected INTERFACE)

  target_link_libraries(osquery_utils_expected INTERFACE
    global_cxx_settings
    osquery_utils_debug
    osquery_utils_error
    thirdparty_boost
  )

  set(public_header_files
    expected.h
  )

  generateIncludeNamespace(osquery_utils_expected "osquery" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_utils_expected_main()
