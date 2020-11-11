# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryCarverTestsMain)
  generateOsqueryCarverTestsTest()
endfunction()

function(generateOsqueryCarverTestsTest)
  add_osquery_executable(osquery_carver_tests-test carver_tests.cpp)

  target_link_libraries(osquery_carver_tests-test PRIVATE
    osquery_cxx_settings
    osquery_carver
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_hashing
    osquery_utils_conversions
    osquery_utils_info
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryCarverTestsMain()
