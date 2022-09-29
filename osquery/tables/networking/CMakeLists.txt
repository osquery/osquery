# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesNetworkingMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryTablesNetworking()
endfunction()

function(generateOsqueryTablesNetworking)
  set(source_files
    curl.cpp
    curl_certificate.cpp
    etc_hosts.cpp
    etc_protocols.cpp
    etc_services.cpp
    listening_ports.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/dns_resolvers.cpp
      posix/interfaces.cpp
      posix/utils.cpp
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      linux/arp_cache.cpp
      linux/interface_ip.cpp
      linux/iptables.cpp
      linux/iptc_proxy.c
      linux/process_open_sockets.cpp
      linux/routes.cpp
    )

  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      darwin/interface_ip.cpp
      darwin/routes.cpp
      darwin/wifi.mm
      darwin/wifi_status.mm
      darwin/wifi_survey.mm
      darwin/wifi_utils.mm
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/arp_cache.cpp
      windows/connectivity.cpp
      windows/windows_firewall_rules.cpp
      windows/interfaces.cpp
      windows/process_open_sockets.cpp
      windows/routes.cpp
    )
  endif()

  add_osquery_library(osquery_tables_networking EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_tables_networking PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_filesystem
    osquery_remote_utility
    osquery_utils
    osquery_utils_conversions
    osquery_tables_system_systemtable
    thirdparty_boost
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND platform_deps
      thirdparty_libiptables
    )
  endif()

  target_link_libraries(osquery_tables_networking PUBLIC
    ${platform_deps}
  )

  if(DEFINED PLATFORM_POSIX)
    set(public_header_files
      posix/interfaces.h
      posix/utils.h
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND public_header_files
      linux/inet_diag.h
      linux/iptc_proxy.h
    )

  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND public_header_files
      darwin/wifi_utils.h
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND public_header_files
      windows/interfaces.h
      windows/windows_firewall_rules.h
    )
  endif()

  generateIncludeNamespace(osquery_tables_networking "osquery/tables/networking" "FULL_PATH" ${public_header_files})

  add_test(NAME osquery_tables_networking_tests_networkingtablestests-test COMMAND osquery_tables_networking_tests_networkingtablestests-test)

  set(networkingtablestests-test_env
    "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
    "TEST_HELPER_SCRIPTS_DIR=${CMAKE_BINARY_DIR}/tools/tests"
    "OSQUERY_PYTHON_INTERPRETER_PATH=${OSQUERY_PYTHON_EXECUTABLE}"
  )

  set_tests_properties(
    osquery_tables_networking_tests_networkingtablestests-test
    PROPERTIES ENVIRONMENT "${networkingtablestests-test_env}"
  )

  if(DEFINED PLATFORM_MACOS)
    add_test(NAME osquery_tables_networking_tests_wifitests-test COMMAND osquery_tables_networking_tests_wifitests-test)

    set_tests_properties(
      osquery_tables_networking_tests_wifitests-test
      PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
    )
  elseif(DEFINED PLATFORM_LINUX)
    add_test(NAME osquery_tables_networking_tests_iptablestests-test COMMAND osquery_tables_networking_tests_iptablestests-test)
  elseif(DEFINED PLATFORM_WINDOWS)
    add_test(NAME osquery_tables_networking_tests_windowsfirewallrulestests-test COMMAND osquery_tables_networking_tests_windowsfirewallrulestests-test)
  endif()

endfunction()

osqueryTablesNetworkingMain()
