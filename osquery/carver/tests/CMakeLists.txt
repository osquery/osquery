# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryCarverTestsMain)
  generateOsqueryCarverTestsTest()
endfunction()

function(generateOsqueryCarverTestsTest)
  add_osquery_executable(osquery_carver_tests-test carver_tests.cpp)

  target_link_libraries(osquery_carver_tests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_carver
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_hashing
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_info
    plugins_config_tlsconfig
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryCarverTestsMain()
