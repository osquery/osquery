# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryCoreTestsMain)
  generateOsqueryCoreTestsTest()
  generateOsqueryCoreTestsWatcherpermissionstestsTest()
endfunction()

function(generateOsqueryCoreTestsTest)
  add_osquery_executable(osquery_core_tests-test
    flags_tests.cpp
    system_test.cpp
    tables_tests.cpp
    query_tests.cpp
    process_tests.cpp
  )

  target_link_libraries(osquery_core_tests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_registry
    osquery_utils
    osquery_config_tests_testutils
    osquery_sql_tests_sqltestutils
    tests_helper
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryCoreTestsWatcherpermissionstestsTest)
  set(source_files
    watcher_tests.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files posix/permissions_tests.cpp)
  endif()

  add_osquery_executable(osquery_core_tests_watcherpermissionstests-test
    ${source_files}
  )

  target_link_libraries(osquery_core_tests_watcherpermissionstests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_init
    osquery_process
    osquery_registry
    osquery_utils
    tests_helper
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryCoreTestsMain()
