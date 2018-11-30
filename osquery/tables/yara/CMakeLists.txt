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

function(osquery_tables_yara_main)
  generateOsqueryTablesYara()
endfunction()

function(generateOsqueryTablesYara)
  set(source_files
    yara.cpp
    yara_utils.cpp
  )

  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      yara_events.cpp
    )
  endif()

  add_library(osquery_tables_yara EXCLUDE_FROM_ALL
    ${source_files}
  )

  enableLinkWholeArchive(osquery_tables_yara)

  target_link_libraries(osquery_tables_yara PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_config
    osquery_dispatcher
    osquery_events
    osquery_logger
    osquery_registry
    osquery_utils_config
    thirdparty_boost
    thirdparty_yara
  )

  set(public_header_files
    yara_utils.h
  )

  generateIncludeNamespace(osquery_tables_yara "osquery/tables/yara" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_tables_yara_main()
