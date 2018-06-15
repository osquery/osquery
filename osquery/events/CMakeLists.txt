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


  file(GLOB OSQUERY_EVENTS_DARWIN "darwin/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_darwin ${OSQUERY_EVENTS_DARWIN})
elseif(FREEBSD)
  # no-op
  # no files for FREEBSD
elseif(WINDOWS)
  ADD_OSQUERY_LINK_CORE("wevtapi.lib")
  file(GLOB OSQUERY_EVENTS_WINDOWS "windows/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_windows ${OSQUERY_EVENTS_WINDOWS})
else()
  ADD_OSQUERY_LINK_ADDITIONAL("udev")
  ADD_OSQUERY_LINK_ADDITIONAL("audit")

  file(GLOB OSQUERY_EVENTS_LINUX "linux/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_linux ${OSQUERY_EVENTS_LINUX})
endif()

ADD_OSQUERY_LIBRARY(TRUE osquery_events
  events.cpp
)

file(GLOB OSQUERY_EVENTS_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_EVENTS_TESTS})

if(NOT WINDOWS)
  file(GLOB OSQUERY_EVENTS_BENCHMARKS "benchmarks/*.cpp")
  if (LINUX)
    file(GLOB OSQUERY_EVENTS_PLATFORM_BENCHMARKS "linux/benchmarks/*.cpp")
  elseif (DARWIN)
    file(GLOB OSQUERY_EVENTS_PLATFORM_BENCHMARKS "darwin/benchmarks/*.cpp")
  endif()
  ADD_OSQUERY_BENCHMARK(
    ${OSQUERY_EVENTS_BENCHMARKS}
    ${OSQUERY_EVENTS_PLATFORM_BENCHMARKS}
  )

endif()

if(APPLE)
  file(GLOB OSQUERY_DARWIN_EVENTS_TESTS "darwin/tests/*.cpp")
  ADD_OSQUERY_TEST(FALSE ${OSQUERY_DARWIN_EVENTS_TESTS})
elseif(LINUX)
  file(GLOB OSQUERY_LINUX_EVENTS_TESTS "linux/tests/*.cpp")
  ADD_OSQUERY_TEST(FALSE ${OSQUERY_LINUX_EVENTS_TESTS})
elseif(WINDOWS)
  file(GLOB OSQUERY_WINDOWS_EVENTS_TESTS "windows/tests/*.cpp")
  ADD_OSQUERY_TEST(FALSE ${OSQUERY_WINDOWS_EVENTS_TESTS})
endif()
