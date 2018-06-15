#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

ADD_OSQUERY_LIBRARY(TRUE osquery_database "")

target_sources(osquery_database
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/database.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/plugins/ephemeral.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/plugins/ephemeral.h"
)

ADD_OSQUERY_TEST(TRUE
  "${CMAKE_CURRENT_LIST_DIR}/tests/database_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/plugin_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/plugin_tests.h"
  "${CMAKE_CURRENT_LIST_DIR}/tests/results_tests.cpp"
)

if(NOT OSQUERY_BUILD_SDK_ONLY)
  ADD_OSQUERY_LIBRARY(FALSE osquery_database_plugins "")

  target_sources(osquery_database_plugins
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/plugins/rocksdb.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/plugins/rocksdb.h"
      "${CMAKE_CURRENT_LIST_DIR}/plugins/sqlite.h"
      "${CMAKE_CURRENT_LIST_DIR}/plugins/sqlite.cpp"
  )

  target_compile_definitions(osquery_database_plugins
    PRIVATE
      "-DROCKSDB_LITE=1"
  )
endif()

ADD_OSQUERY_TEST(FALSE
  "${CMAKE_CURRENT_LIST_DIR}/tests/plugin_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/plugin_tests.h"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/rocksdb_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/sqlite_tests.cpp"
)

ADD_OSQUERY_BENCHMARK(
  "${CMAKE_CURRENT_LIST_DIR}/benchmarks/database_benchmarks.cpp"
)
