# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryDispatcherMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryDispatcher()
endfunction()

function(generateOsqueryDispatcher)
  add_osquery_library(osquery_dispatcher EXCLUDE_FROM_ALL
    dispatcher.cpp
    distributed_runner.cpp
    scheduler.cpp
  )

  target_link_libraries(osquery_dispatcher PUBLIC
    global_cxx_settings
    osquery_core
    osquery_logger_datalogger
    osquery_process
    osquery_profiler
    osquery_sql
    osquery_utils
    osquery_utils_conversions
    plugins_config_parsers
    thirdparty_googletest_headers
  )

  set(public_header_files
    distributed_runner.h
    scheduler.h
  )

  generateIncludeNamespace(osquery_dispatcher "osquery/dispatcher" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_dispatcher_tests-test COMMAND osquery_dispatcher_tests-test)
  add_test(NAME osquery_dispatcher_tests_scheduler-test COMMAND osquery_dispatcher_tests_scheduler-test)
endfunction()

osqueryDispatcherMain()
