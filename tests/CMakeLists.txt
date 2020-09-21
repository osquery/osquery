# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(testsMain)
  add_subdirectory("cppcheck")

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("integration/tables")
    generateTestsHelper()
  endif()
endfunction()

function(generateTestsHelper)
  add_osquery_library(tests_helper EXCLUDE_FROM_ALL test_util.cpp)

  set(public_header_files
    test_util.h
  )

  generateIncludeNamespace(tests_helper "osquery/tests" "FILE_ONLY" ${public_header_files})

  target_link_libraries(tests_helper PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_config
    osquery_database
    osquery_filesystem
    osquery_process
    osquery_sql
    osquery_utils
    osquery_utils_conversions
    osquery_utils_system_time
    specs_tables
    thirdparty_boost
    thirdparty_googletest_headers
  )
endfunction()

testsMain()
