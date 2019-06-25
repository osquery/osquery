# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osquerySystemNetworkMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsquerySystemNetworkHostname()
endfunction()

function(generateOsquerySystemNetworkHostname)
  add_osquery_library(osquery_system_network_hostname EXCLUDE_FROM_ALL hostname.cpp)

  target_link_libraries(osquery_system_network_hostname PUBLIC
    global_cxx_settings
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
