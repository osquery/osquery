# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osquerySystemNetworkTestsMain)
  generateOsquerySystemNetworkTestsHostnamehostidentitytestsTest()
endfunction()

function(generateOsquerySystemNetworkTestsHostnamehostidentitytestsTest)
  add_osquery_executable(osquery_system_network_tests_hostnamehostidentitytests-test host_identity.cpp)

  target_link_libraries(osquery_system_network_tests_hostnamehostidentitytests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_system_network_hostname
    osquery_utils_info
    tests_helper
    thirdparty_googletest
    thirdparty_boost
  )
endfunction()

osquerySystemNetworkTestsMain()
