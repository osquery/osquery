# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryDatabaseMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryDatabase()
endfunction()

function(generateOsqueryDatabase)
  add_osquery_library(osquery_database EXCLUDE_FROM_ALL
    database.cpp
  )

  target_link_libraries(osquery_database PUBLIC
    global_cxx_settings
    osquery_core
    osquery_utils
    osquery_utils_conversions
    thirdparty_boost
  )

  add_test(NAME osquery_database_tests-test COMMAND osquery_database_tests-test)
  add_test(NAME osquery_database_tests_results-test COMMAND osquery_database_tests_results-test)
endfunction()

osqueryDatabaseMain()
