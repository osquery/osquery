# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryDevtoolsTestsMain)
  generateOsqueryDevtoolsTestsPrintertestsTest()
endfunction()

function(generateOsqueryDevtoolsTestsPrintertestsTest)
  add_osquery_executable(osquery_devtools_tests_printertests-test printer_tests.cpp)

  target_link_libraries(osquery_devtools_tests_printertests-test PRIVATE
    global_cxx_settings
    osquery_database
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_devtools
    plugins_config_tlsconfig
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryDevtoolsTestsMain()
