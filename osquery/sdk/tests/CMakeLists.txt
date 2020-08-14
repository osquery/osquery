# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osquerySdkTestsMain)
  generateOsquerySdkTestsPluginsdktestsTest()
endfunction()

function(generateOsquerySdkTestsPluginsdktestsTest)
  add_osquery_executable(osquery_sdk_tests_pluginsdktests-test registry_tests.cpp)

  target_link_libraries(osquery_sdk_tests_pluginsdktests-test PUBLIC
    osquery_cxx_settings
    osquery_extensions_implthrift
    osquery_sdk_pluginsdk
    thirdparty_googletest
  )
endfunction()

osquerySdkTestsMain()
