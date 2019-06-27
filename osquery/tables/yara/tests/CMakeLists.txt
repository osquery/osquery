# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesYaraTestsMain)

  # We deviate from what there's in the BUCK file because compiling empty sources doesn't work
  if(DEFINED PLATFORM_POSIX)
    generateOsqueryTablesYaraTestsTest()
  endif()
endfunction()

function(generateOsqueryTablesYaraTestsTest)

  set(source_files yara_tests.cpp)

  add_osquery_executable(osquery_tables_yara_tests-test ${source_files})

  target_link_libraries(osquery_tables_yara_tests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_database
    osquery_filesystem
    osquery_remote_httpclient
    osquery_remote_tests_remotetestutils
    osquery_tables_yara_yaratable
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    plugins_database_ephemeral
    thirdparty_boost
    thirdparty_googletest
  )
endfunction()

osqueryTablesYaraTestsMain()
