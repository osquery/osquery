# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryDatabaseTestsMain)
  generateOsqueryDatabaseTestsTest()
  generateOsqueryDatabaseTestsResultsTest()
endfunction()

function(generateOsqueryDatabaseTestsTest)
  add_osquery_executable(osquery_database_tests-test database.cpp)

  target_link_libraries(osquery_database_tests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_registry
    osquery_utils_json
    plugins_database_ephemeral
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
    osquery_registry
    osquery_utils_json
    osquery_sql_tests_sqltestutils
    plugins_database_ephemeral
    thirdparty_googletest
  )
endfunction()

osqueryDatabaseTestsMain()
