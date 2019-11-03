# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryConfigTestsMain)
  generateOsqueryConfigTestsTestUtils()
  generateOsqueryConfigTestsTest()
endfunction()

function(generateOsqueryConfigTestsTestUtils)
  add_osquery_library(osquery_config_tests_testutils EXCLUDE_FROM_ALL test_utils.cpp)

  set(public_header_files
    test_utils.h
  )

  generateIncludeNamespace(osquery_config_tests_testutils "osquery/config/tests" "FILE_ONLY" ${public_header_files})

  target_link_libraries(osquery_config_tests_testutils PRIVATE
    osquery_cxx_settings
    osquery_filesystem
    osquery_utils_json
    osquery_utils_system
  )
endfunction()

function(generateOsqueryConfigTestsTest)
  add_osquery_executable(osquery_config_tests-test
    config_tests.cpp
    packs_tests.cpp
  )

  target_link_libraries(osquery_config_tests-test PRIVATE
    osquery_cxx_settings
    osquery_config
    osquery_config_configplugin
    osquery_extensions_implthrift
    osquery_utils_system
    plugins_database_ephemeral
    thirdparty_googletest
    osquery_filesystem_mockfilestructure
    osquery_config_tests_testutils
    osquery_tools_tests_conffiles
  )
endfunction()

osqueryConfigTestsMain()
