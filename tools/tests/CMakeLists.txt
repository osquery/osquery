# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryToolsTestsMain)
  generateCopyFileTarget("osquery_tools_tests_conffiles" "REGEX" "*.conf" "${TEST_CONFIGS_DIR}")
  generateCopyFileTarget("osquery_tools_tests_configfiles" "REGEX" "*.config" "${TEST_CONFIGS_DIR}")
  generateCopyFileTarget("osquery_tools_tests_plistfiles" "REGEX" "*.plist" "${TEST_CONFIGS_DIR}")
  generateCopyFileTarget("osquery_tools_tests_testfiles" "REGEX" "*" "${TEST_CONFIGS_DIR}")
  generateCopyFileTarget("osquery_tools_tests_awsfiles" "REGEX" "aws/*" "${TEST_CONFIGS_DIR}")
endfunction()

osqueryToolsTestsMain()
