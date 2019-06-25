# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryEventsTestsMain)
  generateOsqueryEventsTestsTest()
  generateOsqueryEventsTestsEventsdatabasetestsTest()

  if(DEFINED PLATFORM_LINUX)
    generateOsqueryEventsTestsSyslogtestsTest()
    generateOsqueryEventsTestsAudittestsTest()
    generateOsqueryEventsTestsProcessfileeventstestsTest()
    generateOsqueryEventsTestsInotifytestsTest()
  endif()

  if(DEFINED PLATFORM_MACOS)
    generateOsqueryEventsTestsFseventstestsTest()
  endif()

endfunction()

function(generateOsqueryEventsTestsTest)
  add_osquery_executable(osquery_events_tests-test events_tests.cpp)

  target_link_libraries(osquery_events_tests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_events
    osquery_filesystem
    osquery_remote_tests_remotetestutils
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsEventsdatabasetestsTest)
  add_osquery_executable(osquery_events_tests_eventsdatabasetests-test events_database_tests.cpp)

  target_link_libraries(osquery_events_tests_eventsdatabasetests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_events
    osquery_filesystem
    osquery_remote_tests_remotetestutils
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsSyslogtestsTest)
  add_osquery_executable(osquery_events_tests_syslogtests-test linux/syslog_tests.cpp)

  target_link_libraries(osquery_events_tests_syslogtests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_events
    osquery_filesystem
    osquery_remote_tests_remotetestutils
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsAudittestsTest)
  add_osquery_executable(osquery_events_tests_audittests-test linux/audit_tests.cpp)

  target_link_libraries(osquery_events_tests_audittests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_events
    osquery_filesystem
    osquery_remote_tests_remotetestutils
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsProcessfileeventstestsTest)
  add_osquery_executable(osquery_events_tests_processfileeventstests-test linux/process_file_events_tests.cpp)

  target_link_libraries(osquery_events_tests_processfileeventstests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_events
    osquery_filesystem
    osquery_remote_tests_remotetestutils
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsInotifytestsTest)
  add_osquery_executable(osquery_events_tests_inotifytests-test linux/inotify_tests.cpp)

  target_link_libraries(osquery_events_tests_inotifytests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_events
    osquery_filesystem
    osquery_remote_tests_remotetestutils
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsFseventstestsTest)
  add_osquery_executable(osquery_events_tests_fseventstests-test darwin/fsevents_tests.cpp)

  target_link_libraries(osquery_events_tests_fseventstests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_remote_tests_remotetestutils
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryEventsTestsMain()
