# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsSchemerJsonTestsMain)
  generateOsqueryUtilsSchemerJsonTestsSchemerjsontestsTest()
endfunction()

function(generateOsqueryUtilsSchemerJsonTestsSchemerjsontestsTest)
  add_osquery_executable(osquery_utils_schemer_json_tests_schemerjsontests-test schemer_json.cpp)

  target_link_libraries(osquery_utils_schemer_json_tests_schemerjsontests-test PRIVATE
    global_cxx_settings
    osquery_utils_schemer_json
    thirdparty_googletest
  )
endfunction()

osqueryUtilsSchemerJsonTestsMain()
