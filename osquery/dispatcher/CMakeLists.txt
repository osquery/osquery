# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryDispatcherMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryDispatcher()
  generateOsqueryDistributedAndScheduler()
endfunction()

function(generateOsqueryDispatcher)
  add_osquery_library(osquery_dispatcher EXCLUDE_FROM_ALL
    dispatcher.cpp
  )

  target_link_libraries(osquery_dispatcher PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_process
    osquery_utils
    thirdparty_boost
    thirdparty_googletest_headers
  )

  set(public_header_files
    dispatcher.h
  )

  generateIncludeNamespace(osquery_dispatcher "osquery/dispatcher" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_dispatcher_tests-test COMMAND osquery_dispatcher_tests-test)
endfunction()

function(generateOsqueryDistributedAndScheduler)
  add_osquery_library(osquery_dispatcher_scheduler EXCLUDE_FROM_ALL
    distributed_runner.cpp
    scheduler.cpp
  )

  target_link_libraries(osquery_dispatcher_scheduler PUBLIC
    osquery_cxx_settings
    osquery_carver
    osquery_core
    osquery_database
    osquery_distributed
    osquery_logger_datalogger
    osquery_process
    osquery_profiler
    osquery_sql
    osquery_utils
    osquery_utils_conversions
    osquery_worker_system_linux_memory
    plugins_config_parsers
    thirdparty_boost
    thirdparty_googletest_headers
  )

  set(public_header_files
    distributed_runner.h
    scheduler.h
  )

  generateIncludeNamespace(osquery_dispatcher_scheduler "osquery/dispatcher" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_dispatcher_tests_scheduler-test COMMAND osquery_dispatcher_tests_scheduler-test)
endfunction()

osqueryDispatcherMain()
