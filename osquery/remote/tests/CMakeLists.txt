# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryRemoteTestsMain)
  generateOsqueryRemoteTestsRemotetestsutils()
  generateOsqueryRemoteTestsRequeststestsTest()
endfunction()

function(generateOsqueryRemoteTestsRemotetestsutils)
  add_osquery_library(osquery_remote_tests_remotetestutils EXCLUDE_FROM_ALL test_utils.cpp)

  set(public_header_files
    test_utils.h
  )

  generateIncludeNamespace(osquery_remote_tests_remotetestutils "osquery/remote/tests" "FILE_ONLY" ${public_header_files})

  target_link_libraries(osquery_remote_tests_remotetestutils PUBLIC
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_info
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_killswitch_killswitchfilesystem
    tests_helper
  )
endfunction()

function(generateOsqueryRemoteTestsRequeststestsTest)
  add_osquery_executable(osquery_remote_tests_requeststests-test requests_tests.cpp)

  target_link_libraries(osquery_remote_tests_requeststests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_remote_enroll_tlsenroll
    osquery_remote_tests_remotetestutils
    osquery_utils_conversions
    osquery_utils_info
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_killswitch_killswitchfilesystem
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryRemoteTestsMain()
