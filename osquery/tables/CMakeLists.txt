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

function(osquery_tables_main)
  add_subdirectory("applications")
  add_subdirectory("cloud")
  add_subdirectory("events")
  add_subdirectory("forensic")
  add_subdirectory("lldpd")
  add_subdirectory("networking")
  add_subdirectory("sleuthkit")
  add_subdirectory("smart")
  add_subdirectory("system")
  add_subdirectory("utility")
  add_subdirectory("yara")
  
  generateOsqueryTables()
endfunction()

function(generateOsqueryTables)
  add_library(osquery_tables INTERFACE)

  if(DEFINED PLATFORM_POSIX)
    target_link_libraries(osquery_tables INTERFACE
      osquery_tables_sleuthkit
      osquery_tables_yara
      osquery_tables_lldpd
    )
  endif()

  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS)
    target_link_libraries(osquery_tables INTERFACE
      osquery_tables_cloud
      osquery_tables_smart
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    target_link_libraries(osquery_tables INTERFACE
      osquery_tables_cloud
    )
  endif()

  target_link_libraries(osquery_tables INTERFACE
    osquery_tables_applications
    osquery_tables_events
    osquery_tables_forensic
    osquery_tables_networking
    osquery_tables_system
    osquery_tables_utility
  )
endfunction()

osquery_tables_main()
