# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryPluginsDatabaseMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generatePluginsDatabaseRocksdbplugin()
  generatePluginsDatabaseSqliteplugin()
endfunction()

function(generatePluginsDatabaseRocksdbplugin)
  add_osquery_library(plugins_database_rocksdbplugin EXCLUDE_FROM_ALL
    rocksdb.cpp
  )

  enableLinkWholeArchive(plugins_database_rocksdbplugin)

  target_link_libraries(plugins_database_rocksdbplugin PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_registry
    osquery_utils
    thirdparty_googletest_headers
    thirdparty_rocksdb
  )

  set(public_header_files
    rocksdb.h
  )

  generateIncludeNamespace(plugins_database_rocksdbplugin "plugins/database" "FILE_ONLY" ${public_header_files})

  add_test(NAME plugins_database_tests_rocksdbtests-test COMMAND plugins_database_tests_rocksdbtests-test)
endfunction()

function(generatePluginsDatabaseSqliteplugin)
  add_osquery_library(plugins_database_sqliteplugin EXCLUDE_FROM_ALL
    sqlite.cpp
  )

  enableLinkWholeArchive(plugins_database_sqliteplugin)

  target_link_libraries(plugins_database_sqliteplugin PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_filesystem
    osquery_registry
    osquery_utils
    thirdparty_sqlite
  )

  set(public_header_files
    sqlite.h
  )

  generateIncludeNamespace(plugins_database_sqliteplugin "plugins/database" "FILE_ONLY" ${public_header_files})

  add_test(NAME plugins_database_tests_sqliteplugintests-test COMMAND plugins_database_tests_sqliteplugintests-test)
endfunction()

osqueryPluginsDatabaseMain()
