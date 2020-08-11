# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsSchemerJsonTestsMain)
  generateOsqueryUtilsSchemerJsonTestsSchemerjsontestsTest()
endfunction()

function(generateOsqueryUtilsSchemerJsonTestsSchemerjsontestsTest)
  add_osquery_executable(osquery_utils_schemer_json_tests_schemerjsontests-test schemer_json.cpp)

  target_link_libraries(osquery_utils_schemer_json_tests_schemerjsontests-test PRIVATE
    osquery_cxx_settings
    osquery_utils_schemer_json
    thirdparty_googletest
  )
endfunction()

osqueryUtilsSchemerJsonTestsMain()
