# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryRegistryTestsMain)
  osqueryRegistryTestsTest()
endfunction()

function(osqueryRegistryTestsTest)
  add_osquery_executable(osquery_registry_tests-test registry.cpp)

  target_link_libraries(osquery_registry_tests-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_registry
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryRegistryTestsMain()
