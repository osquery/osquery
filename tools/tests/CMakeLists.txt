# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryToolsTestsMain)
  if(OSQUERY_BUILD_TESTS)
    set(configs_base_path "${CMAKE_CURRENT_SOURCE_DIR}/configs")
    generateCopyFileTarget("osquery_tools_tests_conffiles" "${configs_base_path}" "REGEX" "*.conf" "${TEST_CONFIGS_DIR}")
    generateCopyFileTarget("osquery_tools_tests_configfiles" "${configs_base_path}" "REGEX" "*.config" "${TEST_CONFIGS_DIR}")
    generateCopyFileTarget("osquery_tools_tests_plistfiles" "${configs_base_path}" "REGEX" "*.plist" "${TEST_CONFIGS_DIR}")
    generateCopyFileTarget("osquery_tools_tests_testfiles" "${configs_base_path}" "REGEX" "*" "${TEST_CONFIGS_DIR}")
    generateCopyFileTarget("osquery_tools_tests_awsfiles" "${configs_base_path}" "REGEX" "aws/*" "${TEST_CONFIGS_DIR}")
  endif()
endfunction()

osqueryToolsTestsMain()
