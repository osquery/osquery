# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesSmartTestsMain)
  if(DEFINED PLATFORM_POSIX)
    generateOsqueryTablesSmartTestsSmartdrivestestsTest()
  endif()
endfunction()

function(generateOsqueryTablesSmartTestsSmartdrivestestsTest)
  add_osquery_executable(osquery_tables_smart_tests_smartdrivestests-test smart_drives_tests.cpp)

  target_link_libraries(osquery_tables_smart_tests_smartdrivestests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_config
    osquery_config_tests_testutils
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_tables_events_eventstable
    plugins_config_tlsconfig
    plugins_config_parsers
    specs_tables
    thirdparty_smartmontools
    thirdparty_googletest
  )
endfunction()

osqueryTablesSmartTestsMain()
