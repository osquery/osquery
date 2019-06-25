# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryCoreTestsMain)
  generateOsqueryCoreTestsFlagstestsTest()
  generateOsqueryCoreTestsSystemtestsTest()
  generateOsqueryCoreTestsTablestestsTest()
  generateOsqueryCoreTestsWatcherpermissionstestsTest()
  generateOsqueryCoreTestsQuerytestsTest()
endfunction()

function(generateOsqueryCoreTestsFlagstestsTest)
  add_osquery_executable(osquery_core_tests_flagstests-test flags_tests.cpp)

  target_link_libraries(osquery_core_tests_flagstests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_dispatcher
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    tests_helper
    osquery_utils_info
    plugins_config_tlsconfig
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryCoreTestsSystemtestsTest)
  add_osquery_executable(osquery_core_tests_systemtests-test system_test.cpp)

  target_link_libraries(osquery_core_tests_systemtests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_dispatcher
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    tests_helper
    osquery_utils_info
    plugins_config_tlsconfig
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryCoreTestsTablestestsTest)
  add_osquery_executable(osquery_core_tests_tablestests-test tables_tests.cpp)

  target_link_libraries(osquery_core_tests_tablestests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_dispatcher
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    tests_helper
    osquery_utils_info
    plugins_config_tlsconfig
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryCoreTestsWatcherpermissionstestsTest)

  set(source_files
    watcher_tests.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files posix/permissions_tests.cpp)
  endif()

  add_osquery_executable(osquery_core_tests_watcherpermissionstests-test ${source_files})

  target_link_libraries(osquery_core_tests_watcherpermissionstests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_dispatcher
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_process
    osquery_registry
    osquery_remote_enroll_tlsenroll
    tests_helper
    osquery_utils_info
    plugins_config_tlsconfig
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryCoreTestsQuerytestsTest)
  add_osquery_executable(osquery_core_tests_querytests-test query_tests.cpp)

  target_link_libraries(osquery_core_tests_querytests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_dispatcher
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_sql_tests_sqltestutils
    tests_helper
    osquery_utils_info
    plugins_config_tlsconfig
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryCoreTestsMain()
