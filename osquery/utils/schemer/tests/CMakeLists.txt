# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsSchemerTestsMain)
  generateOsqueryUtilsSchemerTestsSchemertestsTest()
endfunction()

function(generateOsqueryUtilsSchemerTestsSchemertestsTest)
  add_osquery_executable(osquery_utils_schemer_tests_schemertests-test schemer.cpp)

  target_link_libraries(osquery_utils_schemer_tests_schemertests-test PRIVATE
    osquery_cxx_settings
    osquery_utils_conversions_to
    osquery_utils_schemer
    thirdparty_googletest
  )
endfunction()

osqueryUtilsSchemerTestsMain()
