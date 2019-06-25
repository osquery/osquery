# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osquerySystemNetworkTestsMain)
  generateOsquerySystemNetworkTestsHostnamehostidentitytestsTest()
endfunction()

function(generateOsquerySystemNetworkTestsHostnamehostidentitytestsTest)
  add_osquery_executable(osquery_system_network_tests_hostnamehostidentitytests-test host_identity.cpp)

  target_link_libraries(osquery_system_network_tests_hostnamehostidentitytests-test PRIVATE
    global_cxx_settings
    osquery_system_network_hostname
    thirdparty_boost
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_dispatcher
    osquery_distributed
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_info
    plugins_config_tlsconfig
    tests_helper
    specs_tables
    thirdparty_googletest
  )
endfunction()

osquerySystemNetworkTestsMain()
