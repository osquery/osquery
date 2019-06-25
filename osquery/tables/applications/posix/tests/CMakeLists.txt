# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesApplicationsPosixTestsMain)
  if(DEFINED PLATFORM_POSIX)
    generateOsqueryTablesApplicationsPosixTestsPrometheusmetricstestsTest()
  endif()
endfunction()

function(generateOsqueryTablesApplicationsPosixTestsPrometheusmetricstestsTest)
  add_osquery_executable(osquery_tables_applications_posix_tests_prometheusmetricstests-test prometheus_metrics_tests.cpp)

  target_link_libraries(osquery_tables_applications_posix_tests_prometheusmetricstests-test PRIVATE
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
    osquery_tables_applications
    plugins_config_tlsconfig
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryTablesApplicationsPosixTestsMain()
