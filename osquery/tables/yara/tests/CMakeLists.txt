# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesYaraTestsMain)

  # We deviate from what there's in the BUCK file because compiling empty sources doesn't work
  generateOsqueryTablesYaraTestsTest()
endfunction()

function(generateOsqueryTablesYaraTestsTest)

  set(source_files yara_tests.cpp)

  add_osquery_executable(osquery_tables_yara_tests-test ${source_files})

  target_link_libraries(osquery_tables_yara_tests-test PRIVATE
    osquery_cxx_settings
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
    thirdparty_boost
    thirdparty_googletest
  )
endfunction()

osqueryTablesYaraTestsMain()
