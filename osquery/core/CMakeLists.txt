#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

target_compile_definitions(libosquery
  PRIVATE
    "-DROCKSDB_LITE=1"
)

target_sources(libosquery
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/base64.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/base64.h"
    "${CMAKE_CURRENT_LIST_DIR}/conversions.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/conversions.h"
    "${CMAKE_CURRENT_LIST_DIR}/database/database.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/database/database.h"
    "${CMAKE_CURRENT_LIST_DIR}/database/in_memory_database.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/database/in_memory_database.h"
    "${CMAKE_CURRENT_LIST_DIR}/database/rocksdb_database.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/database/rocksdb_database.h"
    "${CMAKE_CURRENT_LIST_DIR}/flags.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/hashing.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/hashing.h"
    "${CMAKE_CURRENT_LIST_DIR}/init.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/json.h"
    "${CMAKE_CURRENT_LIST_DIR}/process.h"
    "${CMAKE_CURRENT_LIST_DIR}/query.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/status.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/system.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/tables.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/utils.h"
    "${CMAKE_CURRENT_LIST_DIR}/watcher.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/watcher.h"
)

if(APPLE)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/darwin/conversions.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/iokit.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/iokit.hpp"
  )
endif()

if(POSIX)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/posix/initializer.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/posix/process_ops.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/posix/process.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/posix/utils.cpp"
  )
endif()

if(WINDOWS)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/windows/initializer.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/windows/process_ops.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/windows/process_ops.h"
      "${CMAKE_CURRENT_LIST_DIR}/windows/process.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/windows/handle.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/windows/utils.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/windows/wmi.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/windows/wmi.h"
  )
endif()

ADD_OSQUERY_TEST_CORE(
  "${CMAKE_CURRENT_LIST_DIR}/database/tests/in_memory_database_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/database/tests/rocksdb_database_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/base64_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/conversions_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/error_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/exptected_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/flags_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/process_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/query_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/status_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/system_test.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/tables_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/time_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/watcher_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/utils_tests.cpp"
)

if(POSIX) 
  ADD_OSQUERY_TEST_CORE(
    "${CMAKE_CURRENT_LIST_DIR}/tests/posix/permissions_tests.cpp"
  )   
endif()
