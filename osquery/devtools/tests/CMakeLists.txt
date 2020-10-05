# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryDevtoolsTestsMain)
  generateOsqueryDevtoolsTestsPrintertestsTest()
endfunction()

function(generateOsqueryDevtoolsTestsPrintertestsTest)
  add_osquery_executable(osquery_devtools_tests_printertests-test printer_tests.cpp)

  target_link_libraries(osquery_devtools_tests_printertests-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_devtools
    plugins_config_tlsconfig
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryDevtoolsTestsMain()
