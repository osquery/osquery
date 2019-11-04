# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryDatabaseTestsMain)
  generateOsqueryDatabaseTestsTest()
endfunction()

function(generateOsqueryDatabaseTestsTest)
  add_osquery_executable(osquery_database_tests-test
    database.cpp
    results.cpp
  )

  target_link_libraries(osquery_database_tests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_registry
    osquery_utils_json
    osquery_sql_tests_sqltestutils
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryDatabaseTestsMain()
