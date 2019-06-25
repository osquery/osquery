# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryNumericmonitoringTestsMain)
  osqueryNumericmonitoringTestsTest()
  osqueryNumericmonitoringTestsPreaggregationcacheTest()
endfunction()

function(osqueryNumericmonitoringTestsTest)
  add_osquery_executable(osquery_numericmonitoring_tests-test numeric_monitoring.cpp)

  target_link_libraries(osquery_numericmonitoring_tests-test PRIVATE
    global_cxx_settings
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_numericmonitoring
    osquery_registry
    osquery_remote_enroll_tlsenroll
    plugins_config_tlsconfig
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(osqueryNumericmonitoringTestsPreaggregationcacheTest)
  add_osquery_executable(osquery_numericmonitoring_tests_preaggregationcache-test pre_aggregation_cache.cpp)

  target_link_libraries(osquery_numericmonitoring_tests_preaggregationcache-test PRIVATE
    global_cxx_settings
    osquery_database
    osquery_dispatcher
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_numericmonitoring
    osquery_registry
    osquery_remote_enroll_tlsenroll
    plugins_config_tlsconfig
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryNumericmonitoringTestsMain()
