# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryCoreTestsMain)
  generateOsqueryCoreTestsMergedtestsTest()

  # TODO: This test should actually run as root, but it's currently broken when using that user
  if(DEFINED PLATFORM_POSIX)
    generateOsqueryCoreTestsPermissionstestsTest()
  endif()

  generateOsqueryCoreTestsProcesstestsTest()

  if(DEFINED PLATFORM_WINDOWS)
    generateOsqueryCoreTestsWmitestsTest()
  endif()
endfunction()

function(generateOsqueryCoreTestsMergedtestsTest)
  set(source_files
    flags_tests.cpp
    system_test.cpp
    tables_tests.cpp
    watcher_tests.cpp
    query_tests.cpp
  )

  add_osquery_executable(osquery_core_tests_mergedtests-test ${source_files})

  target_link_libraries(osquery_core_tests_mergedtests-test PRIVATE
    osquery_core
    osquery_cxx_settings
    osquery_extensions
    osquery_extensions_implthrift
    osquery_main
    osquery_process
    osquery_registry
    osquery_sql_tests_sqltestutils
    osquery_utils_info
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryCoreTestsProcesstestsTest)
  add_osquery_executable(osquery_core_tests_processtests-test process_tests.cpp)

  target_link_libraries(osquery_core_tests_processtests-test PRIVATE
    osquery_cxx_settings
    osquery_extensions
    osquery_extensions_implthrift
    osquery_main
    osquery_process
    tests_helper
    thirdparty_googletest
  )
endfunction()

# generateOsqueryCoreTestsPermissionstestsTest is posix only, and cannot be merged
function(generateOsqueryCoreTestsPermissionstestsTest)

  set(source_files
    posix/permissions_tests.cpp
  )

  add_osquery_executable(osquery_core_tests_permissionstests-test ${source_files})

  target_link_libraries(osquery_core_tests_permissionstests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_extensions
    osquery_extensions_implthrift
    osquery_process
    osquery_registry
    tests_helper
    osquery_utils_info
    thirdparty_googletest
  )
endfunction()

# generateOsqueryCoreTestsWmitestsTest is windows only, and cannot merge
function(generateOsqueryCoreTestsWmitestsTest)
  add_osquery_executable(osquery_core_tests_wmitests-test windows/wmi_tests.cpp)

  target_link_libraries(osquery_core_tests_wmitests-test PRIVATE
    osquery_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_sql_tests_sqltestutils
    osquery_utils_info
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryCoreTestsMain()
