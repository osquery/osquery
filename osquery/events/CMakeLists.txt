#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

if(APPLE)
  ADD_OSQUERY_LINK_ADDITIONAL("-framework CoreServices")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework SystemConfiguration")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework IOKit")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework DiskArbitration")

  ADD_OSQUERY_LIBRARY(FALSE osquery_events_darwin 
    "${CMAKE_CURRENT_LIST_DIR}/darwin/diskarbitration.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/darwin/diskarbitration.h"
    "${CMAKE_CURRENT_LIST_DIR}/darwin/event_taps.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/darwin/event_taps.h"
    "${CMAKE_CURRENT_LIST_DIR}/darwin/fsevents.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/darwin/fsevents.h"
    "${CMAKE_CURRENT_LIST_DIR}/darwin/iokit.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/darwin/iokit.h"
    "${CMAKE_CURRENT_LIST_DIR}/darwin/openbsm.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/darwin/openbsm.h"
    "${CMAKE_CURRENT_LIST_DIR}/darwin/scnetwork.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/darwin/scnetwork.h"
  )
elseif(FREEBSD)
  # no-op
  # no files for FREEBSD
elseif(WINDOWS)
  ADD_OSQUERY_LINK_CORE("wevtapi.lib")
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_windows 
    "${CMAKE_CURRENT_LIST_DIR}/windows/windows_event_log.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/windows/windows_event_log.h"
  )
else()
  ADD_OSQUERY_LINK_ADDITIONAL("udev")
  ADD_OSQUERY_LINK_ADDITIONAL("audit")

  ADD_OSQUERY_LIBRARY(FALSE osquery_events_linux
    "${CMAKE_CURRENT_LIST_DIR}/linux/auditdnetlink.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/linux/auditdnetlink.h"
    "${CMAKE_CURRENT_LIST_DIR}/linux/auditeventpublisher.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/linux/auditeventpublisher.h"
    "${CMAKE_CURRENT_LIST_DIR}/linux/inotify.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/linux/inotify.h"
    "${CMAKE_CURRENT_LIST_DIR}/linux/syslog.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/linux/syslog.h"
    "${CMAKE_CURRENT_LIST_DIR}/linux/tests"
    "${CMAKE_CURRENT_LIST_DIR}/linux/udev.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/linux/udev.h"
  )
endif()

target_sources(libosquery
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/events.cpp"  
)

ADD_OSQUERY_TEST_CORE(
  "${CMAKE_CURRENT_LIST_DIR}/tests/events_database_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/events_tests.cpp"
)

if(NOT WINDOWS)
  ADD_OSQUERY_BENCHMARK(
    "${CMAKE_CURRENT_LIST_DIR}/benchmarks/events_benchmarks.cpp"
  )
endif()

if(APPLE) 
  ADD_OSQUERY_TEST_ADDITIONAL(
    "${CMAKE_CURRENT_LIST_DIR}/darwin/tests/fsevents_tests.cpp"
  )
elseif(LINUX)
  ADD_OSQUERY_TEST_ADDITIONAL(
    "${CMAKE_CURRENT_LIST_DIR}/linux/tests/audit_tests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/linux/tests/inotify_tests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/linux/tests/process_file_events_tests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/linux/tests/syslog_tests.cpp"
  )
elseif(WINDOWS)
  ADD_OSQUERY_TEST_ADDITIONAL(
    "${CMAKE_CURRENT_LIST_DIR}/windows/tests/windows_event_log_tests.cpp"
  )
endif()
