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

function(osquery_core_sql_main)
  generateOsqueryCoreSql()
endfunction()

function(generateOsqueryCoreSql)
  add_library(osquery_core_sql EXCLUDE_FROM_ALL
    column.cpp
    diff_results.cpp
    query_data.cpp
    query_performance.cpp
    row.cpp
    scheduled_query.cpp
  )

  target_link_libraries(osquery_core_sql PUBLIC
    global_cxx_settings
    osquery_utils_json
    osquery_utils_status
  )

  set(public_header_files
    column.h
    diff_results.h
    query_data.h
    query_performance.h
    row.h
    scheduled_query.h
  )

  generateIncludeNamespace(osquery_core_sql "osquery/core/sql" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_core_sql_main()
