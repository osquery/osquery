# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryNumericmonitoringTestsMain)
  osqueryNumericmonitoringTestsTest()
  osqueryNumericmonitoringTestsPreaggregationcacheTest()
endfunction()

function(osqueryNumericmonitoringTestsTest)
  add_osquery_executable(osquery_numericmonitoring_tests-test numeric_monitoring.cpp)

  target_link_libraries(osquery_numericmonitoring_tests-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_numericmonitoring
    osquery_registry
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(osqueryNumericmonitoringTestsPreaggregationcacheTest)
  add_osquery_executable(osquery_numericmonitoring_tests_preaggregationcache-test pre_aggregation_cache.cpp)

  target_link_libraries(osquery_numericmonitoring_tests_preaggregationcache-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_numericmonitoring
    osquery_registry
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryNumericmonitoringTestsMain()
