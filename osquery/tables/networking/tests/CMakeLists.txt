# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesNetworkingTestsMain)
  generateOsqueryTablesNetworkingTestsMergedtestsTest()
endfunction()

function(generateOsqueryTablesNetworkingTestsMergedtestsTest)
  set(source_files
    networking_tables_tests.cpp
    curl_tests.cpp
  )

  if(DEFINED PLATFORM_MACOS)
    list(APPEND source_files darwin/wifi_tests.mm)
  elseif(DEFINED PLATFORM_LINUX)
    list(APPEND source_files linux/iptables_tests.cpp)
  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files windows/windows_firewall_rules_tests.cpp)
  endif()

  add_osquery_executable(osquery_tables_networking_tests_mergedtests-test ${source_files})

  target_link_libraries(osquery_tables_networking_tests_mergedtests-test PRIVATE
    osquery_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_filesystem
    osquery_remote_httpclient
    osquery_remote_tests_remotetestutils
    osquery_tables_system_systemtable
    osquery_tables_networking
    osquery_utils
    osquery_utils_conversions
    thirdparty_boost
    thirdparty_googletest
  )
endfunction()

osqueryTablesNetworkingTestsMain()
