# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesMain)
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
  
  generateOsqueryTablesTableimplementations()
endfunction()

function(generateOsqueryTablesTableimplementations)
  add_osquery_library(osquery_tables_tableimplementations INTERFACE)

  if(DEFINED PLATFORM_POSIX)
    target_link_libraries(osquery_tables_tableimplementations INTERFACE
      osquery_tables_sleuthkit_sleuthkittable
      osquery_tables_yara_yaratable
      osquery_tables_lldpd_llpdtable
    )
  endif()

  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS)
    target_link_libraries(osquery_tables_tableimplementations INTERFACE
      osquery_tables_cloud
      osquery_tables_smart
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    target_link_libraries(osquery_tables_tableimplementations INTERFACE
      osquery_tables_cloud
    )
  endif()

  target_link_libraries(osquery_tables_tableimplementations INTERFACE
    osquery_tables_applications
    osquery_tables_events_eventstable
    osquery_tables_forensic
    osquery_tables_networking
    osquery_tables_system_systemtable
    osquery_tables_utility_utilitytable
  )
endfunction()

osqueryTablesMain()
