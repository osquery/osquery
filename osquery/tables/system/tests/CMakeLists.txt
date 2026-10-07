# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesSystemTestsMain)
  generateOsqueryTablesSystemTestsMergedtestsTest()
endfunction()

function(generateOsqueryTablesSystemTestsMergedtestsTest)
  set(source_files
    npm_packages_tests.cpp
    system_tables_tests.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/known_hosts_tests.cpp
      posix/shell_history_tests.cpp
      posix/ssh_keys_tests.cpp
      posix/sshd_config_tests.cpp
      posix/sudoers_tests.cpp
      posix/last_tests.cpp
      posix/authorized_keys_tests.cpp
      posix/augeas_tests.cpp
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      linux/apt_sources_tests.cpp
      linux/extended_attributes_tests.cpp
      linux/flatpak_packages_tests.cpp
      linux/md_tables_tests.cpp
      linux/pacman_packages_tests.cpp
      linux/snap_packages_tests.cpp
      linux/pci_devices_tests.cpp
      linux/pcidb_tests.cpp
      linux/portage_tests.cpp
      linux/processes_tests.cpp
      linux/rpm_packages_tests.cpp
      linux/secureboot_certificates_tests.cpp
      linux/selinux_settings_tests.cpp
      linux/yum_sources_tests.cpp
    )
  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      darwin/apps_tests.cpp
      darwin/asl_tests.cpp
      darwin/certificates_tests.cpp
      darwin/extended_attributes_tests.cpp
      darwin/firewall_tests.cpp
      darwin/launchd_tests.cpp
      darwin/macports_packages_tests.cpp
      darwin/mdfind_tests.cpp
      darwin/packages_tests.cpp
      darwin/processes_tests.cpp
      darwin/smc_tests.cpp
      darwin/startup_items_tests.mm
      darwin/system_extensions_test.cpp
      darwin/signature_tests.mm
      darwin/keychain_test.cpp
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/certificates_tests.cpp
      windows/processes_tests.cpp
      windows/programs_tests.cpp
      windows/registry_tests.cpp
      windows/token_privileges_tests.cpp
      windows/windows_eventlog_tests.cpp
      windows/windows_optional_features_tests.cpp
      windows/windows_update_history_tests.cpp
      windows/startup_items_tests.cpp
    )
  endif()

  add_osquery_executable(osquery_tables_system_tests_mergedtests-test ${source_files})

  set(link_libraries
    osquery_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_hashing
    osquery_registry
    osquery_sql
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    tests_helper
    thirdparty_googletest
    thirdparty_openssl
  )

  if(DEFINED PLATFORM_MACOS)
    list(APPEND link_libraries
      osquery_utils_plist
      osquery_utils_system_profiler
    )
  endif()

  target_link_libraries(osquery_tables_system_tests_mergedtests-test PRIVATE
    ${link_libraries}
  )

  if(DEFINED PLATFORM_MACOS)
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
    add_dependencies(osquery_tables_system_tests_mergedtests-test
      unsigned_test_builder
    )
  endif()

  if(DEFINED PLATFORM_POSIX)
    get_property(augeas_lenses_path GLOBAL PROPERTY AUGEAS_LENSES_FOLDER_PATH)

    add_custom_target(osquery_tables_system_tests_augeaslenses
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${TEST_CONFIGS_DIR}/augeas/lenses"
      COMMAND "${CMAKE_COMMAND}" -E copy "${augeas_lenses_path}/*.aug" "${TEST_CONFIGS_DIR}/augeas/lenses")

    add_dependencies(osquery_tables_system_tests_mergedtests-test osquery_tables_system_tests_augeaslenses)
    add_dependencies(osquery_tables_system_tests_augeaslenses thirdparty_augeas)
  endif()
endfunction()

osqueryTablesSystemTestsMain()
