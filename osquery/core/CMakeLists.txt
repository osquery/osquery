#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

file(GLOB OSQUERY_CORE_PLATFORM "${PROCESS_FAMILY}/*.cpp")
file(GLOB OSQUERY_CORE_PLATFORM_TESTS "tests/${PROCESS_FAMILY}/*.cpp")

if(APPLE)
  set(OSQUERY_CORE_PLATFORM
    ${OSQUERY_CORE_PLATFORM}
    darwin/conversions_darwin.cpp
    darwin/iokit.cpp
  )
endif()

file(GLOB OSQUERY_CORE "*.cpp")
ADD_OSQUERY_LIBRARY(TRUE osquery_core
  ${OSQUERY_CORE_PLATFORM}
  ${OSQUERY_CORE}
)

file(GLOB OSQUERY_CORE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_CORE_TESTS} ${OSQUERY_CORE_PLATFORM_TESTS})
