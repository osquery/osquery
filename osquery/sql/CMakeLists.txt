# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osquerySqlMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsquerySql()
  generateOsquerySqlCarver()
  generateOsquerySqlSqliteplugin()
endfunction()

function(generateOsquerySqlCarver)
  set(source_files
    sqlite_carver.cpp
  )

  add_osquery_library(osquery_sql_carver EXCLUDE_FROM_ALL
    ${source_files}
  )

  # enableLinkWholeArchive(osquery_sql_carver)

  target_link_libraries(osquery_sql_carver PUBLIC
    osquery_cxx_settings
    osquery_sql
    osquery_carver
    osquery_core
    osquery_core_plugins
    thirdparty_boost
    thirdparty_googletest_headers
    thirdparty_sqlite
    thirdparty_gflags
  )
endfunction()

function(generateOsquerySqlSqliteplugin)
  set(source_files
    sql_plugin_sqlite.cpp
  )

  add_osquery_library(osquery_sql_sqliteplugin EXCLUDE_FROM_ALL
    ${source_files}
  )

  enableLinkWholeArchive(osquery_sql_sqliteplugin)

  target_link_libraries(osquery_sql_sqliteplugin PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    thirdparty_sqlite
  )
endfunction()

function(generateOsquerySql)
  set(source_files
    dynamic_table_row.cpp
    sql.cpp
    sqlite_encoding.cpp
    sqlite_filesystem.cpp
    sqlite_hashing.cpp
    sqlite_math.cpp
    sqlite_util.cpp
    virtual_sqlite_table.cpp
    virtual_table.cpp
  )

  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS OR DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      sqlite_string.cpp
    )
  endif()

  add_osquery_library(osquery_sql EXCLUDE_FROM_ALL
    ${source_files}
  )

  # enableLinkWholeArchive(osquery_sql)

  target_link_libraries(osquery_sql PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_hashing
    osquery_process
    osquery_utils
    osquery_utils_system_errno
    thirdparty_boost
    thirdparty_googletest_headers
    thirdparty_sqlite
    thirdparty_gflags
  )

  target_link_libraries(osquery_sql PRIVATE
    osquery_sql_sqliteplugin
  )

  if(NOT DEFINED PLATFORM_WINDOWS)
    target_link_libraries(osquery_sql PUBLIC
      thirdparty_ssdeep-cpp
    )
  endif()

  set(public_header_files
    dynamic_table_row.h
    sqlite_util.h
    virtual_table.h
  )

  generateIncludeNamespace(osquery_sql "osquery/sql" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_sql_tests-test COMMAND osquery_sql_tests-test)
  add_test(NAME osquery_sql_tests_virtualtabletests-test COMMAND osquery_sql_tests_virtualtabletests-test)
  add_test(NAME osquery_sql_tests_sqliteutilstests-test COMMAND osquery_sql_tests_sqliteutilstests-test)
endfunction()

osquerySqlMain()
