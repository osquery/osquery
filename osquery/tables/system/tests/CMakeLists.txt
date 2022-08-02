# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesSystemTestsMain)

  if(DEFINED PLATFORM_LINUX)
    generateOsqueryTablesSystemLinuxTests()
  endif()

  if(DEFINED PLATFORM_POSIX)
    generateOsqueryTablesSystemPosixTests()
    generateOsqueryTablesSystemTestsAugeasTestsTest()
  endif()

  generateOsqueryTablesSystemTestsSystemtablestestsTest()

  if(DEFINED PLATFORM_MACOS)
    generateOsqueryTablesSystemDarwinTests()
  endif()

  if(DEFINED PLATFORM_WINDOWS)
    generateOsqueryTablesSystemWindowsTests()
  endif()
endfunction()

function(generateOsqueryTablesSystemLinuxTests)
  add_osquery_executable(osquery_tables_system_linux_tests-test
    linux/apt_sources_tests.cpp
    linux/extended_attributes_tests.cpp
    linux/md_tables_tests.cpp
    linux/pci_devices_tests.cpp
    linux/pcidb_tests.cpp
    linux/portage_tests.cpp
    linux/rpm_packages_tests.cpp
    linux/selinux_settings_tests.cpp
    linux/yum_sources_tests.cpp
  )

  target_link_libraries(osquery_tables_system_linux_tests-test PRIVATE
    osquery_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryTablesSystemPosixTests)
  add_osquery_executable(osquery_tables_system_posix_tests-test
    posix/known_hosts_tests.cpp
    posix/shell_history_tests.cpp
    posix/ssh_keys_tests.cpp
    posix/sudoers_tests.cpp
    posix/last_tests.cpp
    posix/authorized_keys_tests.cpp
  )

  target_link_libraries(osquery_tables_system_posix_tests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryTablesSystemTestsSystemtablestestsTest)
  add_osquery_executable(osquery_tables_system_tests_systemtablestests-test
    system_tables_tests.cpp
  )

  target_link_libraries(osquery_tables_system_tests_systemtablestests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryTablesSystemDarwinTests)
  add_osquery_executable(osquery_tables_system_darwin_tests-test
    darwin/apps_tests.cpp
    darwin/asl_tests.cpp
    darwin/certificates_tests.cpp
    darwin/extended_attributes_tests.cpp
    darwin/firewall_tests.cpp
    darwin/launchd_tests.cpp
    darwin/mdfind_tests.cpp
    darwin/packages_tests.cpp
    darwin/processes_tests.cpp
    darwin/smc_tests.cpp
    darwin/startup_items_tests.cpp
    darwin/system_extensions_test.cpp
    darwin/signature_tests.mm
  )

  target_link_libraries(osquery_tables_system_darwin_tests-test PRIVATE
    osquery_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    tests_helper
    thirdparty_googletest
  )

  add_executable(unsigned_test darwin/unsigned_test.cpp)

  add_custom_command(
    OUTPUT "${TEST_CONFIGS_DIR}/unsigned_test"
    DEPENDS unsigned_test
    COMMAND "${CMAKE_COMMAND}" -E copy $<TARGET_FILE:unsigned_test> "${TEST_CONFIGS_DIR}/unsigned_test_temp"
    COMMAND codesign --remove-signature --deep "${TEST_CONFIGS_DIR}/unsigned_test_temp"
    COMMAND "${CMAKE_COMMAND}" -E rename "${TEST_CONFIGS_DIR}/unsigned_test_temp" "${TEST_CONFIGS_DIR}/unsigned_test"
    VERBATIM
    COMMENT "Generating unsigned_test..."
  )

  add_custom_target(unsigned_test_builder
    DEPENDS "${TEST_CONFIGS_DIR}/unsigned_test"
  )

  # Make sure that the data directory is generated before the unsigned_test data
  add_dependencies(unsigned_test_builder
    osquery_tools_tests_configfiles
  )

  # Make sure that the data is built before the test
  add_dependencies(osquery_tables_system_darwin_tests-test
    unsigned_test_builder
  )
endfunction()

function(generateOsqueryTablesSystemWindowsTests)
  add_osquery_executable(osquery_tables_system_windows_tests-test
    windows/certificates_tests.cpp
    windows/registry_tests.cpp
    windows/windows_eventlog_tests.cpp
    windows/windows_optional_features_tests.cpp
    windows/windows_update_history_tests.cpp
  )

  target_link_libraries(osquery_tables_system_windows_tests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryTablesSystemTestsAugeasTestsTest)
  add_osquery_executable(osquery_tables_system_tests_augeastests-test
    posix/augeas_tests.cpp
  )

  target_link_libraries(osquery_tables_system_tests_augeastests-test PRIVATE
    osquery_cxx_settings
    osquery_config_tests_testutils
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_sql
    tests_helper
    thirdparty_googletest
  )

  get_property(augeas_lenses_path GLOBAL PROPERTY AUGEAS_LENSES_FOLDER_PATH)

  add_custom_target(osquery_tables_system_tests_augeaslenses
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${TEST_CONFIGS_DIR}/augeas/lenses"
    COMMAND "${CMAKE_COMMAND}" -E copy "${augeas_lenses_path}/*.aug" "${TEST_CONFIGS_DIR}/augeas/lenses")

  add_dependencies(osquery_tables_system_tests_augeastests-test osquery_tables_system_tests_augeaslenses)
  add_dependencies(osquery_tables_system_tests_augeaslenses thirdparty_augeas)
endfunction()

osqueryTablesSystemTestsMain()
