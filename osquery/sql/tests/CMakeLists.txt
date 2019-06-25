# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osquerySqlMain)
  generateOsquerySqlTestsSqltestutils()
  generateOsquerySqlTestsTest()
  generateOsquerySqlTestsVirtualtableTestsTest()
  generateOsquerySqlTestsSqliteutiltestsTest()
endfunction()

function(generateOsquerySqlTestsSqltestutils)
  add_osquery_library(osquery_sql_tests_sqltestutils EXCLUDE_FROM_ALL sql_test_utils.cpp)

  set(public_header_files
    sql_test_utils.h
  )

  generateIncludeNamespace(osquery_sql_tests_sqltestutils "osquery/sql/tests" "FILE_ONLY" ${public_header_files})

  target_link_libraries(osquery_sql_tests_sqltestutils PUBLIC
    global_cxx_settings
    osquery_database
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_sql
    plugins_config_tlsconfig
    plugins_database_ephemeral
    specs_tables
  )
endfunction()

function(generateOsquerySqlTestsTest)
  add_osquery_executable(osquery_sql_tests-test sql.cpp)

  target_link_libraries(osquery_sql_tests-test PRIVATE
    global_cxx_settings
    osquery_database
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_sql
    osquery_sql_tests_sqltestutils
    plugins_config_tlsconfig
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsquerySqlTestsVirtualtableTestsTest)
  add_osquery_executable(osquery_sql_tests_virtualtabletests-test virtual_table.cpp)

  target_link_libraries(osquery_sql_tests_virtualtabletests-test PRIVATE
    global_cxx_settings
    osquery_database
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_sql
    plugins_config_tlsconfig
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsquerySqlTestsSqliteutiltestsTest)
  add_osquery_executable(osquery_sql_tests_sqliteutilstests-test sqlite_util_tests.cpp)

  target_link_libraries(osquery_sql_tests_sqliteutilstests-test PRIVATE
    global_cxx_settings
    osquery_database
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_sql
    osquery_sql_tests_sqltestutils
    plugins_config_tlsconfig
    specs_tables
    thirdparty_googletest
  )
endfunction()

osquerySqlMain()
