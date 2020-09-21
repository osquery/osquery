# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryRegistryTestsMain)
  osqueryRegistryTestsTest()
endfunction()

function(osqueryRegistryTestsTest)
  add_osquery_executable(osquery_registry_tests-test registry.cpp)

  target_link_libraries(osquery_registry_tests-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryRegistryTestsMain()
