# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsAwsTestsMain)
  generateOsqueryUtilsAwsTestsTest()
endfunction()

function(generateOsqueryUtilsAwsTestsTest)
  add_osquery_executable(osquery_utils_aws_tests-test aws_util_tests.cpp)

  target_link_libraries(osquery_utils_aws_tests-test PRIVATE
    osquery_cxx_settings
    osquery_config_tests_testutils
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_process
    osquery_utils_aws
    osquery_utils_info
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryUtilsAwsTestsMain()
