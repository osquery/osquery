# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

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
    osquery_cxx_settings
    osquery_filesystem
    osquery_utils_json
    osquery_utils_system_env
  )
endfunction()

function(generateOsqueryConfigTestsTest)
  add_osquery_executable(osquery_config_tests-test config_tests.cpp)

  target_link_libraries(osquery_config_tests-test PRIVATE
    osquery_cxx_settings
    osquery_config
    osquery_config_tests_testutils
    osquery_database
    osquery_dispatcher
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem_mockfilestructure
    osquery_registry
    osquery_utils_system_time
    tests_helper
    thirdparty_googletest
  )

endfunction()

function(generateOsqueryConfigTestsPacksTest)
  add_osquery_executable(osquery_config_tests_packs-test packs.cpp)

  target_link_libraries(osquery_config_tests_packs-test PRIVATE
    osquery_cxx_settings
    osquery_config
    osquery_config_tests_testutils
    osquery_database
    osquery_dispatcher
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem_mockfilestructure
    osquery_registry
    osquery_utils_system_time
    tests_helper
    thirdparty_googletest
  )

endfunction()

osqueryConfigTestsMain()
