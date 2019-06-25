# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesSmartMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryTablesSmart()
endfunction()

function(generateOsqueryTablesSmart)

  set(source_files
    smart_drives.cpp
  )

  if(DEFINED PLATFORM_WINDOWS)
    add_osquery_library(osquery_tables_smart INTERFACE)
  else()
    add_osquery_library(osquery_tables_smart EXCLUDE_FROM_ALL
      "${source_files}"
    )

    target_link_libraries(osquery_tables_smart PUBLIC
      global_cxx_settings
      osquery_headers
      osquery_logger
      osquery_sql
      thirdparty_smartmontools
    )
  endif()

  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS)
    set(public_header_files
      smart_drives.h
    )

    generateIncludeNamespace(osquery_tables_smart "osquery/tables/smart" "FILE_ONLY" ${public_header_files})
  endif()

  if(DEFINED PLATFORM_POSIX)
    add_test(NAME osquery_tables_smart_tests_smartdrivestests-test COMMAND osquery_tables_smart_tests_smartdrivestests-test)
  endif()
endfunction()

osqueryTablesSmartMain()
