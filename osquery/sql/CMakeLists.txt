#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

target_sources(libosquery
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/sql.cpp"
)

if(NOT OSQUERY_BUILD_SDK_ONLY)
ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_sql_internal
  "${CMAKE_CURRENT_LIST_DIR}/sqlite_encoding.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/sqlite_filesystem.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/sqlite_hashing.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/sqlite_math.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/sqlite_util.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/sqlite_util.h"
  "${CMAKE_CURRENT_LIST_DIR}/virtual_table.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/virtual_table.h"
  "${CMAKE_CURRENT_LIST_DIR}/virtual_sqlite_table.cpp"
)

if(NOT FREEBSD)
  target_sources(osquery_sql_internal 
    PRIVATE
       "${CMAKE_CURRENT_LIST_DIR}/sqlite_string.cpp"
  )
endif()
if(NOT SKIP_CARVER)
  target_sources(osquery_sql_internal 
    PRIVATE
       "${CMAKE_CURRENT_LIST_DIR}/sqlite_operations.cpp"
  )
endif()
endif()

ADD_OSQUERY_TEST_ADDITIONAL(
  "${CMAKE_CURRENT_LIST_DIR}/tests/sql_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/sqlite_util_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/virtual_table_tests.cpp"
)

ADD_OSQUERY_BENCHMARK(
  "${CMAKE_CURRENT_LIST_DIR}/benchmarks/sql_benchmarks.cpp"
)
