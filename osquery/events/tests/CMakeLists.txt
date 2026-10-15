# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryEventsTestsMain)
  generateOsqueryEventsTestsMergedtestsTest()
endfunction()

function(generateOsqueryEventsTestsMergedtestsTest)
  set(source_files
      events_tests.cpp
      mockedosquerydatabase.cpp
      eventsubscriberplugin.cpp
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      linux/syslog_tests.cpp
      linux/audit_tests.cpp
      linux/socket_events.cpp
      linux/process_file_events_tests.cpp
      linux/inotify_tests.cpp
    )
  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND source_files darwin/fsevents_tests.cpp)
  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files windows/usn_journal_reader_tests.cpp)
  endif()

  add_osquery_executable(osquery_events_tests_mergedtests-test ${source_files})

  target_link_libraries(osquery_events_tests_mergedtests-test PRIVATE
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_cxx_settings
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_tables_system_systemtable
    osquery_utils
    osquery_utils_conversions
    specs_tables
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryEventsTestsMain()
