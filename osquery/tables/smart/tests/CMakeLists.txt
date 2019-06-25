# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesSmartTestsMain)
  if(DEFINED PLATFORM_POSIX)
    generateOsqueryTablesSmartTestsSmartdrivestestsTest()
  endif()
endfunction()

function(generateOsqueryTablesSmartTestsSmartdrivestestsTest)
  add_osquery_executable(osquery_tables_smart_tests_smartdrivestests-test smart_drives_tests.cpp)

  target_link_libraries(osquery_tables_smart_tests_smartdrivestests-test PRIVATE
    global_cxx_settings
    osquery_headers
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
    plugins_database_ephemeral
    specs_tables
    thirdparty_smartmontools
    thirdparty_googletest
  )
endfunction()

osqueryTablesSmartTestsMain()
