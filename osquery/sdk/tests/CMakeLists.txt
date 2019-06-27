# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osquerySdkTestsMain)
  generateOsquerySdkTestsPluginsdktestsTest()
endfunction()

function(generateOsquerySdkTestsPluginsdktestsTest)
  add_osquery_executable(osquery_sdk_tests_pluginsdktests-test registry_tests.cpp)

  target_link_libraries(osquery_sdk_tests_pluginsdktests-test PUBLIC
    global_cxx_settings
    osquery_extensions_implthrift
    osquery_sdk_pluginsdk
    thirdparty_googletest
  )
endfunction()

osquerySdkTestsMain()
