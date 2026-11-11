# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryPluginsDatabaseTestsMain)
  generatePluginsDatabaseTestsMergedtestsTest()
endfunction()

function(generatePluginsDatabaseTestsMergedtestsTest)
  set(source_files
    sqlite.cpp
    rocksdb.cpp
  )

  add_osquery_executable(plugins_database_tests_mergedtests-test ${source_files})

  target_link_libraries(plugins_database_tests_mergedtests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_database_tests_databasetestutils
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_utils_json
    plugins_database_sqliteplugin
    plugins_database_rocksdbplugin
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryPluginsDatabaseTestsMain()
