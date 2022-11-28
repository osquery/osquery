# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesMain)
  add_subdirectory("applications")
  add_subdirectory("cloud")
  add_subdirectory("events")
  add_subdirectory("forensic")
  add_subdirectory("networking")
  add_subdirectory("sleuthkit")
  add_subdirectory("system")
  add_subdirectory("utility")
  add_subdirectory("yara")

  generateOsqueryTablesTableimplementations()
endfunction()

function(generateOsqueryTablesTableimplementations)
  add_osquery_library(osquery_tables_tableimplementations INTERFACE)

  if(DEFINED PLATFORM_POSIX)
    target_link_libraries(osquery_tables_tableimplementations INTERFACE
      osquery_tables_yara_yaratable
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    target_link_libraries(osquery_tables_tableimplementations INTERFACE
      osquery_tables_yara_yaratable
    )
  endif()

  if(OSQUERY_BUILD_AWS)
    target_link_libraries(osquery_tables_tableimplementations INTERFACE
      osquery_tables_cloud_aws
    )
  endif()

  target_link_libraries(osquery_tables_tableimplementations INTERFACE
    osquery_tables_cloud_azure
    osquery_tables_cloud_ycloud
  )

  target_link_libraries(osquery_tables_tableimplementations INTERFACE
    osquery_tables_applications
    osquery_tables_events_eventstable
    osquery_tables_forensic
    osquery_tables_networking
    osquery_tables_system_systemtable
    osquery_tables_utility_utilitytable
    osquery_tables_sleuthkit_sleuthkittable
  )
endfunction()

osqueryTablesMain()
