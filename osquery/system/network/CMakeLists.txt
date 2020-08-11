# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osquerySystemNetworkMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsquerySystemNetworkHostname()
endfunction()

function(generateOsquerySystemNetworkHostname)
  add_osquery_library(osquery_system_network_hostname EXCLUDE_FROM_ALL hostname.cpp)

  target_link_libraries(osquery_system_network_hostname PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_utils_schemer
    osquery_utils_status
  )

  set(public_header_files
    hostname.h
  )

  generateIncludeNamespace(osquery_system_network_hostname "osquery/system/network" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_system_network_tests_hostnamehostidentitytests-test COMMAND osquery_system_network_tests_hostnamehostidentitytests-test)
endfunction()

osquerySystemNetworkMain()
