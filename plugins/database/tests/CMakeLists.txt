# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryPluginsDatabaseTestsMain)
  generatePluginsDatabaseTestsSqliteplugintestsTest()
  generatePluginsDatabaseTestsRocksdbtestsTest()
  generatePluginsDatabaseTestsDatabasetestutils()
endfunction()

function(generatePluginsDatabaseTestsSqliteplugintestsTest)
  add_osquery_executable(plugins_database_tests_sqliteplugintests-test sqlite.cpp)

  target_link_libraries(plugins_database_tests_sqliteplugintests-test PRIVATE
    global_cxx_settings
    osquery_core
    osquery_database
    osquery_dispatcher
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_json
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_database_sqliteplugin
    specs_tables
    plugins_database_tests_databasetestutils
    thirdparty_googletest
  )
endfunction()

function(generatePluginsDatabaseTestsRocksdbtestsTest)
  add_osquery_executable(plugins_database_tests_rocksdbtests-test rocksdb.cpp)

  target_link_libraries(plugins_database_tests_rocksdbtests-test PRIVATE
    global_cxx_settings
    osquery_core
    osquery_database
    osquery_dispatcher
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_json
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_database_rocksdbplugin
    specs_tables
    plugins_database_tests_databasetestutils
    thirdparty_googletest
  )
endfunction()

function(generatePluginsDatabaseTestsDatabasetestutils)
  add_osquery_library(plugins_database_tests_databasetestutils EXCLUDE_FROM_ALL utils.cpp)

  set(public_header_files
    utils.h
  )

  generateIncludeNamespace(plugins_database_tests_databasetestutils "plugins/database/tests" "FILE_ONLY" ${public_header_files})

  target_link_libraries(plugins_database_tests_databasetestutils PRIVATE
    osquery_filesystem
    osquery_utils_json
    thirdparty_googletest_headers
  )
endfunction()

osqueryPluginsDatabaseTestsMain()
