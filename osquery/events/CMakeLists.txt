# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryEventsMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryEvents()
  generateOsqueryEventsEventspublishers()
endfunction()

function(generateOsqueryEventsEventspublishers)
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

  add_osquery_library(osquery_events_publishers EXCLUDE_FROM_ALL
    ${source_files}
  )

  enableLinkWholeArchive(osquery_events_publishers)

  target_link_libraries(osquery_events_publishers PUBLIC
    osquery_cxx_settings
    osquery_headers
    osquery_core
    osquery_config
    osquery_config_configplugin
    osquery_events
    osquery_hashing
    osquery_utils
    osquery_utils_system
    thirdparty_boost
  )

  if(DEFINED PLATFORM_LINUX)
    target_link_libraries(osquery_events_publishers PUBLIC
      thirdparty_libaudit
      thirdparty_libudev
      thirdparty_util-linux
    )
  endif()

  set(public_header_files
    pathset.h
  )

  generateIncludeNamespace(osquery_events_publishers "osquery/events" "FILE_ONLY" ${public_header_files})

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

  generateIncludeNamespace(osquery_events_publishers "osquery/events" "FULL_PATH" ${platform_public_header_files})

  if(DEFINED PLATFORM_LINUX)
    add_test(NAME osquery_events_tests_syslogtests-test COMMAND osquery_events_tests_syslogtests-test)
    add_test(NAME osquery_events_tests_audittests-test COMMAND osquery_events_tests_audittests-test)
    add_test(NAME osquery_events_tests_processfileeventstests-test COMMAND osquery_events_tests_processfileeventstests-test)
    add_test(NAME osquery_events_tests_inotifytests-test COMMAND osquery_events_tests_inotifytests-test)
  endif()

  if(DEFINED PLATFORM_MACOS)
    add_test(NAME osquery_events_tests_fseventstests-test COMMAND osquery_events_tests_fseventstests-test)
  endif()

  if(DEFINED PLATFORM_WINDOWS)
    add_test(NAME osquery_events_tests_windowseventlogtests-test COMMAND osquery_events_tests_windowseventlogtests-test)
  endif()
endfunction()

function(generateOsqueryEvents)
  add_osquery_library(osquery_events EXCLUDE_FROM_ALL events.cpp)

  target_link_libraries(osquery_events PUBLIC
    osquery_cxx_settings
    osquery_headers
    osquery_config_configplugin
    osquery_core
    osquery_config
    osquery_dispatcher
    osquery_sql
    osquery_utils_system
  )

  add_test(NAME osquery_events_tests-test COMMAND osquery_events_tests-test)
endfunction()

osqueryEventsMain()
