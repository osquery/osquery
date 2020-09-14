# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryDistributedTests)
  generateOsqueryDistributedTestsTest()
endfunction()

function(generateOsqueryDistributedTestsTest)
  add_osquery_executable(osquery_distributed_tests-test distributed_tests.cpp)

  target_link_libraries(osquery_distributed_tests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_distributed
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_remote_tests_remotetestutils
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_config_tlsconfig
    plugins_distributed_tls_distributedtls
    plugins_remote_enroll_tlsenroll
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryDistributedTests()
