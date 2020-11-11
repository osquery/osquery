# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryDispatcherTestsMain)
  generateOsqueryDispatcherTestsTest()
  generateOsqueryDispatcherTestsSchedulerTest()
endfunction()

function(generateOsqueryDispatcherTestsTest)
  add_osquery_executable(osquery_dispatcher_tests-test dispatcher.cpp)

  target_link_libraries(osquery_dispatcher_tests-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_dispatcher
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryDispatcherTestsSchedulerTest)
  add_osquery_executable(osquery_dispatcher_tests_scheduler-test scheduler.cpp)

    target_link_libraries(osquery_dispatcher_tests_scheduler-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_dispatcher_scheduler
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_utils_system_time
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryDispatcherTestsMain()
