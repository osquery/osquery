# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesEventsMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryTablesEventsEventstable()
endfunction()

function(generateOsqueryTablesEventsEventstable)
  set(source_files
    event_utils.cpp
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      linux/file_events.cpp
      linux/hardware_events.cpp
      linux/process_events.cpp
      linux/process_file_events.cpp
      linux/selinux_events.cpp
      linux/socket_events.cpp
      linux/syslog_events.cpp
      linux/user_events.cpp
    )

  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      darwin/disk_events.cpp
      darwin/file_events.cpp
      darwin/hardware_events.cpp
      darwin/openbsm_events.cpp
      darwin/user_interaction_events.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/powershell_events.cpp
      windows/windows_events.cpp
    )
  endif()

  add_osquery_library(osquery_tables_events_eventstable EXCLUDE_FROM_ALL
    ${source_files}
  )

  enableLinkWholeArchive(osquery_tables_events_eventstable)

  target_link_libraries(osquery_tables_events_eventstable PUBLIC
    osquery_headers
    osquery_config
    osquery_core
    osquery_events
    osquery_logger
    osquery_registry
    osquery_utils_system_uptime
    plugins_config_parsers
    thirdparty_boost
  )

  if(DEFINED PLATFORM_MACOS)
    target_link_libraries(osquery_tables_events_eventstable PUBLIC bsm)
  endif()

  set(public_header_files
    event_utils.h
  )

  generateIncludeNamespace(osquery_tables_events_eventstable "osquery/tables/events" "FILE_ONLY" ${public_header_files})

  if(DEFINED PLATFORM_LINUX)
    set(platform_public_header_files
      linux/process_events.h
      linux/process_file_events.h
      linux/selinux_events.h
      linux/socket_events.h
    )

    generateIncludeNamespace(osquery_tables_events_eventstable "osquery/tables/events" "FULL_PATH" ${platform_public_header_files})

    add_test(NAME osquery_tables_events_tests_selinuxeventstests-test COMMAND osquery_tables_events_tests_selinuxeventstests-test)
  endif()

  add_test(NAME osquery_tables_events_tests_fileeventstests-test COMMAND osquery_tables_events_tests_fileeventstests-test)

  set_tests_properties(
    osquery_tables_events_tests_fileeventstests-test
    PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
  )
endfunction()

osqueryTablesEventsMain()
