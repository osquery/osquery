# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryConfigTestsMain)
  generateOsqueryConfigTestsTestUtils()
  generateOsqueryConfigTestsTest()
  generateOsqueryConfigTestsPacksTest()
endfunction()

function(generateOsqueryConfigTestsTestUtils)
  add_osquery_library(osquery_config_tests_testutils EXCLUDE_FROM_ALL test_utils.cpp)

  set(public_header_files
    test_utils.h
  )

  generateIncludeNamespace(osquery_config_tests_testutils "osquery/config/tests" "FILE_ONLY" ${public_header_files})

  target_link_libraries(osquery_config_tests_testutils PUBLIC
    global_cxx_settings
    osquery_filesystem
    osquery_utils_json
    osquery_utils_system_env
  )
endfunction()

function(generateOsqueryConfigTestsTest)
  add_osquery_executable(osquery_config_tests-test config_tests.cpp)

  target_link_libraries(osquery_config_tests-test PRIVATE
    global_cxx_settings
    osquery_config
    osquery_dispatcher
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem_mockfilestructure
    osquery_killswitch
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_system_time
    plugins_config_tlsconfig
    plugins_database_ephemeral
    specs_tables
    osquery_config_tests_testutils
    osquery_tools_tests_conffiles
    thirdparty_googletest
  )

endfunction()

function(generateOsqueryConfigTestsPacksTest)
  add_osquery_executable(osquery_config_tests_packs-test packs.cpp)

  target_link_libraries(osquery_config_tests_packs-test PRIVATE
    global_cxx_settings
    osquery_config
    osquery_dispatcher
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem_mockfilestructure
    osquery_killswitch
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_system_time
    plugins_config_tlsconfig
    plugins_database_ephemeral
    specs_tables
    osquery_config_tests_testutils
    osquery_tools_tests_conffiles
    thirdparty_googletest
  )

endfunction()

osqueryConfigTestsMain()
