# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryEventsMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryEvents()
  generateOsqueryEventsEventsregistry()
endfunction()

function(generateOsqueryEvents)

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      linux/auditdnetlink.cpp
      linux/auditeventpublisher.cpp
      linux/inotify.cpp
      linux/syslog.cpp
      linux/udev.cpp
    )

  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      darwin/diskarbitration.cpp
      darwin/event_taps.cpp
      darwin/fsevents.cpp
      darwin/iokit.cpp
      darwin/openbsm.cpp
      darwin/scnetwork.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/windows_event_log.cpp
    )
  endif()

  add_osquery_library(osquery_events EXCLUDE_FROM_ALL
    ${source_files}
  )

  enableLinkWholeArchive(osquery_events)

  target_link_libraries(osquery_events PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_core
    osquery_config
    osquery_events_eventsregistry
    osquery_hashing
    osquery_sql
    osquery_utils_conversions
    osquery_utils_expected
    osquery_utils_system_time
    thirdparty_boost
  )

  if(DEFINED PLATFORM_LINUX)
    target_link_libraries(osquery_events PUBLIC
      thirdparty_libaudit
      thirdparty_libudev
      thirdparty_util-linux
    )
  endif()

  set(public_header_files
    pathset.h
  )

  generateIncludeNamespace(osquery_events "osquery/events" "FILE_ONLY" ${public_header_files})

  if(DEFINED PLATFORM_LINUX)
    set(platform_public_header_files
      linux/auditdnetlink.h
      linux/auditeventpublisher.h
      linux/inotify.h
      linux/process_events.h
      linux/process_file_events.h
      linux/selinux_events.h
      linux/socket_events.h
      linux/syslog.h
      linux/udev.h
    )

  elseif(DEFINED PLATFORM_MACOS)
    set(platform_public_header_files
      darwin/diskarbitration.h
      darwin/event_taps.h
      darwin/fsevents.h
      darwin/iokit.h
      darwin/openbsm.h
      darwin/scnetwork.h
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    set(platform_public_header_files
      windows/windows_event_log.h
    )
  endif()

  generateIncludeNamespace(osquery_events "osquery/events" "FULL_PATH" ${platform_public_header_files})

  add_test(NAME osquery_events_tests_eventsdatabasetests-test COMMAND osquery_events_tests_eventsdatabasetests-test)

  if(DEFINED PLATFORM_LINUX)
    add_test(NAME osquery_events_tests_syslogtests-test COMMAND osquery_events_tests_syslogtests-test)
    add_test(NAME osquery_events_tests_audittests-test COMMAND osquery_events_tests_audittests-test)
    add_test(NAME osquery_events_tests_processfileeventstests-test COMMAND osquery_events_tests_processfileeventstests-test)
    add_test(NAME osquery_events_tests_inotifytests-test COMMAND osquery_events_tests_inotifytests-test)
  endif()

  if(DEFINED PLATFORM_MACOS)
    add_test(NAME osquery_events_tests_fseventstests-test COMMAND osquery_events_tests_fseventstests-test)
  endif()
endfunction()

function(generateOsqueryEventsEventsregistry)
  add_osquery_library(osquery_events_eventsregistry EXCLUDE_FROM_ALL events.cpp)

  target_link_libraries(osquery_events_eventsregistry PUBLIC
    global_cxx_settings
    osquery_core
    osquery_dispatcher
    osquery_sql
    osquery_headers
  )

  add_test(NAME osquery_events_tests-test COMMAND osquery_events_tests-test)
endfunction()

osqueryEventsMain()
