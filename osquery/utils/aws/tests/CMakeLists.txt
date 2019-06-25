# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsAwsTestsMain)
  generateOsqueryUtilsAwsTestsTest()
endfunction()

function(generateOsqueryUtilsAwsTestsTest)
  add_osquery_executable(osquery_utils_aws_tests-test aws_util_tests.cpp)

  target_link_libraries(osquery_utils_aws_tests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_dispatcher
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_process
    osquery_remote_enroll_tlsenroll
    osquery_utils_aws
    osquery_utils_info
    plugins_config_tlsconfig
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
    osquery_tools_tests_awsfiles
  )
endfunction()

osqueryUtilsAwsTestsMain()
