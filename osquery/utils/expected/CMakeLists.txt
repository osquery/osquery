# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsExpectedMain)
  if(BUILD_TESTING)
    generateOsqueryUtilsExpectedExpectedtestsTest()
  endif()

  generateOsqueryUtilsExpected()
endfunction()

function(generateOsqueryUtilsExpected)
  add_osquery_library(osquery_utils_expected INTERFACE)

  target_link_libraries(osquery_utils_expected INTERFACE
    global_cxx_settings
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
    global_cxx_settings
    osquery_utils_expected
    thirdparty_googletest
  )
endfunction()

osqueryUtilsExpectedMain()
