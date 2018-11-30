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

function(osquery_utils_json_main)
  generateOsqueryUtilsJson()
endfunction()

function(generateOsqueryUtilsJson)
  add_library(osquery_utils_json EXCLUDE_FROM_ALL
    json.cpp
  )

  target_link_libraries(osquery_utils_json PUBLIC
    global_cxx_settings
    osquery_utils
    osquery_utils_conversions
    osquery_utils_status
    osquery_utils_system
    thirdparty_rapidjson
  )

  target_compile_definitions(osquery_utils_json PUBLIC
    RAPIDJSON_NO_SIZETYPEDEFINE
    RAPIDJSON_HAS_STDSTRING=1
  )

  set(public_header_files
    json.h
  )

  generateIncludeNamespace(osquery_utils_json "osquery/utils" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_utils_json_main()
