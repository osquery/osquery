# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsSchemerTestsMain)
  generateOsqueryUtilsSchemerTestsSchemertestsTest()
endfunction()

function(generateOsqueryUtilsSchemerTestsSchemertestsTest)
  add_osquery_executable(osquery_utils_schemer_tests_schemertests-test schemer.cpp)

  target_link_libraries(osquery_utils_schemer_tests_schemertests-test PRIVATE
    global_cxx_settings
    osquery_utils_conversions_to
    osquery_utils_schemer
    thirdparty_googletest
  )
endfunction()

osqueryUtilsSchemerTestsMain()
