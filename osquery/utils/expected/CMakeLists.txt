# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsExpectedMain)
  if(OSQUERY_BUILD_TESTS)
    generateOsqueryUtilsExpectedExpectedtestsTest()
  endif()

  generateOsqueryUtilsExpected()
endfunction()

function(generateOsqueryUtilsExpected)
  add_osquery_library(osquery_utils_expected INTERFACE)

  target_link_libraries(osquery_utils_expected INTERFACE
    osquery_cxx_settings
    osquery_utils_debug
    osquery_utils_error
    thirdparty_boost
  )

  set(public_header_files
    expected.h
  )

  generateIncludeNamespace(osquery_utils_expected "osquery/utils/expected" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_utils_expected_expectedtests-test COMMAND osquery_utils_expected_expectedtests-test)

endfunction()

function(generateOsqueryUtilsExpectedExpectedtestsTest)
  add_osquery_executable(osquery_utils_expected_expectedtests-test tests/expected.cpp)

  target_link_libraries(osquery_utils_expected_expectedtests-test PRIVATE
    osquery_cxx_settings
    osquery_utils_expected
    thirdparty_googletest
  )
endfunction()

osqueryUtilsExpectedMain()
