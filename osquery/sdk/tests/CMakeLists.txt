# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osquerySdkTestsMain)
  generateOsquerySdkTestsTest()
endfunction()

function(generateOsquerySdkTestsTest)
  add_osquery_executable(osquery_sdk_tests-test registry_tests.cpp)

  target_link_libraries(osquery_sdk_tests-test PRIVATE
    osquery_cxx_settings
    osquery_extensions
    osquery_sdk
    thirdparty_googletest
  )
endfunction()

osquerySdkTestsMain()
