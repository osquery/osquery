# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesApplicationsPosixTestsMain)
  if(DEFINED PLATFORM_POSIX)
    generateOsqueryTablesApplicationsPosixTestsPrometheusmetricstestsTest()
  endif()
endfunction()

function(generateOsqueryTablesApplicationsPosixTestsPrometheusmetricstestsTest)
  add_osquery_executable(osquery_tables_applications_posix_tests_prometheusmetricstests-test prometheus_metrics_tests.cpp)

  target_link_libraries(osquery_tables_applications_posix_tests_prometheusmetricstests-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_tables_applications
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryTablesApplicationsPosixTestsMain()
