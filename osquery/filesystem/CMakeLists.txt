#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

if(NOT WINDOWS)
  ADD_OSQUERY_LINK_ADDITIONAL("archive")
  ADD_OSQUERY_LINK_ADDITIONAL("zstd")
else()
  ADD_OSQUERY_LINK_ADDITIONAL("archive_static")
  ADD_OSQUERY_LINK_ADDITIONAL("zstd_static")
endif()

if(APPLE)
  ADD_OSQUERY_LIBRARY(TRUE osquery_filesystem_plist
    darwin/plist.mm
  )

  ADD_OSQUERY_LINK(TRUE "-framework Foundation")
elseif(FREEBSD)
elseif(LINUX)
  ADD_OSQUERY_LIBRARY(TRUE osquery_filesystem_linux
    linux/mem.cpp
    linux/proc.cpp
  )
endif()

file(GLOB OS_FILEOPS_SOURCE "${PROCESS_FAMILY}/*.cpp")

ADD_OSQUERY_LIBRARY(TRUE osquery_filesystem
  filesystem.cpp
  ${OS_FILEOPS_SOURCE}
)

ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_filesystem_compression
  file_compression.cpp
)

file(GLOB OSQUERY_FILESYSTEM_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_FILESYSTEM_TESTS})

if(APPLE)
  file(GLOB OSQUERY_DARWIN_FILESYSTEM_TESTS "darwin/tests/*.cpp")
  ADD_OSQUERY_TEST(TRUE ${OSQUERY_DARWIN_FILESYSTEM_TESTS})

  file(GLOB OSQUERY_DARWIN_FILESYSTEM_BENCHMARKS "darwin/benchmarks/*.cpp")
  ADD_OSQUERY_BENCHMARK(${OSQUERY_DARWIN_FILESYSTEM_BENCHMARKS})
endif()
