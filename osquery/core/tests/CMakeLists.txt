# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryCoreTestsMain)
  generateOsqueryCoreTestsFlagstestsTest()
  generateOsqueryCoreTestsSystemtestsTest()
  generateOsqueryCoreTestsTablestestsTest()

  # TODO: This test should actually run as root, but it's currently broken when using that user
  if(DEFINED PLATFORM_POSIX)
    generateOsqueryCoreTestsPermissionstestsTest()
  endif()

  generateOsqueryCoreTestsWatchertestsTest()
  generateOsqueryCoreTestsQuerytestsTest()
  generateOsqueryCoreTestsProcesstestsTest()

  if(DEFINED PLATFORM_WINDOWS)
    generateOsqueryCoreTestsWmitestsTest()
  endif()
endfunction()

function(generateOsqueryCoreTestsFlagstestsTest)
  add_osquery_executable(osquery_core_tests_flagstests-test flags_tests.cpp)

  target_link_libraries(osquery_core_tests_flagstests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_utils_info
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryCoreTestsSystemtestsTest)
  add_osquery_executable(osquery_core_tests_systemtests-test system_test.cpp)

  target_link_libraries(osquery_core_tests_systemtests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_utils_info
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryCoreTestsTablestestsTest)
  add_osquery_executable(osquery_core_tests_tablestests-test tables_tests.cpp)

  target_link_libraries(osquery_core_tests_tablestests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    tests_helper
    osquery_utils_info
    thirdparty_googletest
  )
endfunction()

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

function(generateOsqueryCoreTestsWatchertestsTest)
  set(source_files
    watcher_tests.cpp
  )

  add_osquery_executable(osquery_core_tests_watchertests-test ${source_files})

  target_link_libraries(osquery_core_tests_watchertests-test PRIVATE
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

function(generateOsqueryCoreTestsQuerytestsTest)
  add_osquery_executable(osquery_core_tests_querytests-test query_tests.cpp)

  target_link_libraries(osquery_core_tests_querytests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_sql_tests_sqltestutils
    tests_helper
    osquery_utils_info
    thirdparty_googletest
  )
endfunction()

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

osqueryCoreTestsMain()
