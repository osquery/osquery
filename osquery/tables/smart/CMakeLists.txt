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

function(osquery_tables_smart_main)
  generateOsqueryTablesSmart()
endfunction()

function(generateOsqueryTablesSmart)
  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS)
    set(source_files
      smart_drives.cpp
    )
  endif()

  add_library(osquery_tables_smart EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_tables_smart PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_logger
    osquery_sql
    thirdparty_smartmontools
  )

  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS)
    set(public_header_files
      smart_drives.h
    )

    generateIncludeNamespace(osquery_tables_smart "osquery/tables/smart" "FILE_ONLY" ${public_header_files})
  endif()
endfunction()

osquery_tables_smart_main()
