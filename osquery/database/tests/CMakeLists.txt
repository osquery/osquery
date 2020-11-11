# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryDatabaseTestsMain)
  generateOsqueryDatabaseTestsTest()
  generateOsqueryDatabaseTestsResultsTest()
  generateOsqueryDatabaseTestsDatabasetestutils()
endfunction()

function(generateOsqueryDatabaseTestsTest)
  add_osquery_executable(osquery_database_tests-test database.cpp)

  target_link_libraries(osquery_database_tests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_utils_json
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryDatabaseTestsResultsTest)
  add_osquery_executable(osquery_database_tests_results-test results.cpp)

  target_link_libraries(osquery_database_tests_results-test PRIVATE
    osquery_cxx_settings
    osquery_core_sql
    osquery_core
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_utils_json
    osquery_sql_tests_sqltestutils
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryDatabaseTestsDatabasetestutils)
  add_osquery_library(osquery_database_tests_databasetestutils EXCLUDE_FROM_ALL test_utils.cpp)

  set(public_header_files
    test_utils.h
  )

  generateIncludeNamespace(osquery_database_tests_databasetestutils "osquery/database/tests" "FILE_ONLY" ${public_header_files})

  target_link_libraries(osquery_database_tests_databasetestutils PRIVATE
    osquery_filesystem
    osquery_registry
    osquery_utils_json
    thirdparty_googletest_headers
  )
endfunction()

osqueryDatabaseTestsMain()
