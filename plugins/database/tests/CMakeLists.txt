# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryPluginsDatabaseTestsMain)
  generatePluginsDatabaseTestsSqliteplugintestsTest()
  generatePluginsDatabaseTestsRocksdbtestsTest()
endfunction()

function(generatePluginsDatabaseTestsSqliteplugintestsTest)
  add_osquery_executable(plugins_database_tests_sqliteplugintests-test sqlite.cpp)

  target_link_libraries(plugins_database_tests_sqliteplugintests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_database_tests_databasetestutils
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_utils_json
    plugins_database_sqliteplugin
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generatePluginsDatabaseTestsRocksdbtestsTest)
  add_osquery_executable(plugins_database_tests_rocksdbtests-test rocksdb.cpp)

  target_link_libraries(plugins_database_tests_rocksdbtests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_database_tests_databasetestutils
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_utils_json
    plugins_database_rocksdbplugin
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryPluginsDatabaseTestsMain()
