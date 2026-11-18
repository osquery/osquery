# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryDispatcherTestsMain)
  generateOsqueryDispatcherTestsMergedtestsTest()
endfunction()

function(generateOsqueryDispatcherTestsMergedtestsTest)
  set(source_files
    dispatcher.cpp
    scheduler.cpp
  )

  add_osquery_executable(osquery_dispatcher_tests_mergedtests-test ${source_files})

  target_link_libraries(osquery_dispatcher_tests_mergedtests-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_dispatcher
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
