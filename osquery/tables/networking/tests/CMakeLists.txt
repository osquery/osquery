# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesNetworkingTestsMain)
  generateOsqueryTablesNetworkingTestsNetworkingtablestestsTest()

  if(DEFINED PLATFORM_MACOS)
    generateOsqueryTablesNetworkingTestsWifitestsTest()
  elseif(DEFINED PLATFORM_LINUX)
    generateOsqueryTablesNetworkingTestsIptablestestsTest()
  endif()
endfunction()

function(generateOsqueryTablesNetworkingTestsNetworkingtablestestsTest)
  add_osquery_executable(osquery_tables_networking_tests_networkingtablestests-test networking_tables_tests.cpp)

  target_link_libraries(osquery_tables_networking_tests_networkingtablestests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_database
    osquery_filesystem
    osquery_remote_httpclient
    osquery_remote_tests_remotetestutils
    osquery_tables_system_systemtable
    osquery_tables_networking
    osquery_utils
    osquery_utils_conversions
    plugins_database_ephemeral
    thirdparty_boost
    thirdparty_googletest
    osquery_tools_tests_testfiles
  )
endfunction()

function(generateOsqueryTablesNetworkingTestsWifitestsTest)
  add_osquery_executable(osquery_tables_networking_tests_wifitests-test darwin/wifi_tests.mm)

  target_link_libraries(osquery_tables_networking_tests_wifitests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_filesystem
    osquery_tables_system_systemtable
    osquery_tables_networking
    osquery_remote_httpclient
    osquery_remote_tests_remotetestutils
    osquery_utils
    osquery_utils_conversions
    plugins_database_ephemeral
    thirdparty_boost
    thirdparty_googletest
    osquery_tools_tests_plistfiles
  )
endfunction()

function(generateOsqueryTablesNetworkingTestsIptablestestsTest)
  add_osquery_executable(osquery_tables_networking_tests_iptablestests-test linux/iptables_tests.cpp)

  target_link_libraries(osquery_tables_networking_tests_iptablestests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_filesystem
    osquery_remote_httpclient
    osquery_remote_tests_remotetestutils
    osquery_tables_networking
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    plugins_database_ephemeral
    thirdparty_boost
    thirdparty_googletest
  )
endfunction()

osqueryTablesNetworkingTestsMain()
