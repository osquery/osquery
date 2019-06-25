# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(testsMain)
  add_subdirectory("integration/tables")

  generateTestsHelper()
endfunction()

function(generateTestsHelper)
  add_osquery_library(tests_helper EXCLUDE_FROM_ALL test_util.cpp)

  set(public_header_files
    test_util.h
  )

  generateIncludeNamespace(tests_helper "osquery/tests" "FILE_ONLY" ${public_header_files})

  target_link_libraries(tests_helper PUBLIC
    global_cxx_settings
    osquery_core
    osquery_filesystem
    osquery_process
    osquery_remote_serializers_serializerjson
    osquery_sql
    osquery_utils
    osquery_utils_conversions
    osquery_utils_system_time
    plugins_database_ephemeral
    specs_tables
    thirdparty_boost
    thirdparty_googletest_headers
  )
endfunction()

testsMain()
