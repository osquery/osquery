# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesEventsTestsMain)
  generateOsqueryTablesEventsTestsFileeventstestsTest()

  if(DEFINED PLATFORM_LINUX)
    generateOsqueryTablesEventsTestsSelinuxeventstestsTest()
  endif()
endfunction()

function(generateOsqueryTablesEventsTestsFileeventstestsTest)
  add_osquery_executable(osquery_tables_events_tests_fileeventstests-test file_events_tests.cpp)

  target_link_libraries(osquery_tables_events_tests_fileeventstests-test PRIVATE
    global_cxx_settings
    osquery_headers
    osquery_config
    osquery_config_tests_testutils
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_tables_events_eventstable
    plugins_config_tlsconfig
    plugins_config_parsers
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryTablesEventsTestsSelinuxeventstestsTest)
  add_osquery_executable(osquery_tables_events_tests_selinuxeventstests-test linux/selinux_events_tests.cpp)

  target_link_libraries(osquery_tables_events_tests_selinuxeventstests-test PRIVATE
    global_cxx_settings
    osquery_headers
    osquery_core
    osquery_config
    osquery_config_tests_testutils
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_tables_events_eventstable
    plugins_config_tlsconfig
    plugins_config_parsers
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryTablesEventsTestsMain()
