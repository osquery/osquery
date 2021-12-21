# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesSmartTestsMain)
  # We want to remove support for smartmontools, so skip support for M1
  if(DEFINED PLATFORM_LINUX OR (DEFINED PLATFORM_MACOS AND NOT "${TARGET_PROCESSOR}" STREQUAL "aarch64"))
    generateOsqueryTablesSmartTestsSmartdrivestestsTest()
  endif()
endfunction()

function(generateOsqueryTablesSmartTestsSmartdrivestestsTest)
  add_osquery_executable(osquery_tables_smart_tests_smartdrivestests-test smart_drives_tests.cpp)

  target_link_libraries(osquery_tables_smart_tests_smartdrivestests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    tests_helper
    thirdparty_smartmontools
    thirdparty_googletest
  )
endfunction()

osqueryTablesSmartTestsMain()
