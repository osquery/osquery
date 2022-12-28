# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesEventsTestsMain)
  generateOsqueryTablesEventsTestsFileeventstestsTest()

  if(DEFINED PLATFORM_LINUX)
    generateOsqueryTablesEventsTestsSeccompeventstestsTest()
    generateOsqueryTablesEventsTestsSelinuxeventstestsTest()
    generateOsqueryTablesEventsTestsProcesseventstestsTest()

    if(OSQUERY_BUILD_BPF)
      generateOsqueryTablesEventsTestsBPFtestsTest()
    endif()

  elseif(DEFINED PLATFORM_WINDOWS)
    generateOsqueryTablesEventsTestsPowershelleventstestsTest()
    generateOsqueryTablesEventsTestsWindowseventstestsTest()
    generateOsqueryTablesEventsTestsETWtestsTest()
  endif()
endfunction()

function(generateOsqueryTablesEventsTestsSeccompeventstestsTest)
  add_osquery_executable(osquery_tables_events_tests_seccompeventstests-test linux/seccomp_events_tests.cpp)

  target_link_libraries(osquery_tables_events_tests_seccompeventstests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_tables_events_eventstable
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryTablesEventsTestsFileeventstestsTest)
  add_osquery_executable(osquery_tables_events_tests_fileeventstests-test file_events_tests.cpp)

  target_link_libraries(osquery_tables_events_tests_fileeventstests-test PRIVATE
    osquery_cxx_settings
    osquery_config
    osquery_config_tests_testutils
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_tables_events_eventstable
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryTablesEventsTestsSelinuxeventstestsTest)
  add_osquery_executable(osquery_tables_events_tests_selinuxeventstests-test linux/selinux_events_tests.cpp)

  target_link_libraries(osquery_tables_events_tests_selinuxeventstests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_tables_events_eventstable
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryTablesEventsTestsProcesseventstestsTest)
  add_osquery_executable(osquery_tables_events_tests_processeventstests-test linux/process_events_tests.cpp)

  target_link_libraries(osquery_tables_events_tests_processeventstests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_tables_events_eventstable
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryTablesEventsTestsBPFtestsTest)
  add_osquery_executable(osquery_tables_events_tests_bpftests-test
    linux/bpf_process_events_tests.cpp
    linux/bpf_socket_events_tests.cpp
  )

  target_link_libraries(osquery_tables_events_tests_bpftests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_tables_events_eventstable
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryTablesEventsTestsETWtestsTest)
  add_osquery_executable(osquery_tables_events_tests_etwtests-test
    windows/etw_process_events_tests.cpp
  )

  target_link_libraries(osquery_tables_events_tests_etwtests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_tables_events_eventstable
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryTablesEventsTestsPowershelleventstestsTest)
  add_osquery_executable(osquery_tables_events_tests_powershelleventstests-test windows/powershell_events_tests.cpp)

  target_link_libraries(osquery_tables_events_tests_powershelleventstests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_tables_events_eventstable
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryTablesEventsTestsWindowseventstestsTest)
  add_osquery_executable(osquery_tables_events_tests_windowseventstests-test windows/windows_events_tests.cpp)

  string(REPLACE "/" "\\\\" test_data_path "${CMAKE_CURRENT_SOURCE_DIR}/windows/data/windows_events")
  target_compile_definitions(osquery_tables_events_tests_windowseventstests-test PRIVATE
    TEST_DATA_PATH=\"${test_data_path}\"
  )

  target_link_libraries(osquery_tables_events_tests_windowseventstests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_tables_events_eventstable
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryTablesEventsTestsMain()
