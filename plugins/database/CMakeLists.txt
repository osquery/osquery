# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryPluginsDatabaseMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generatePluginsDatabaseEphemeral()
  generatePluginsDatabaseRocksdbplugin()
  generatePluginsDatabaseSqliteplugin()
endfunction()

function(generatePluginsDatabaseEphemeral)
  add_osquery_library(plugins_database_ephemeral EXCLUDE_FROM_ALL
    ephemeral.cpp
  )

  enableLinkWholeArchive(plugins_database_ephemeral)

  target_link_libraries(plugins_database_ephemeral PUBLIC
    global_cxx_settings
    osquery_core
    osquery_database
    osquery_registry
    osquery_utils
  )

  set(public_header_files
    ephemeral.h
  )

  generateIncludeNamespace(plugins_database_ephemeral "plugins/database" "FILE_ONLY" ${public_header_files})
endfunction()

function(generatePluginsDatabaseRocksdbplugin)
  add_osquery_library(plugins_database_rocksdbplugin EXCLUDE_FROM_ALL
    rocksdb.cpp
  )

  enableLinkWholeArchive(plugins_database_rocksdbplugin)

  target_link_libraries(plugins_database_rocksdbplugin PUBLIC
    global_cxx_settings
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

  set_tests_properties(plugins_database_tests_rocksdbtests-test PROPERTIES
    DISABLED True
  )
endfunction()

function(generatePluginsDatabaseSqliteplugin)
  add_osquery_library(plugins_database_sqliteplugin EXCLUDE_FROM_ALL
    sqlite.cpp
  )

  enableLinkWholeArchive(plugins_database_sqliteplugin)

  target_link_libraries(plugins_database_sqliteplugin PUBLIC
    global_cxx_settings
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
