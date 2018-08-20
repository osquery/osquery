#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

if(NOT WINDOWS)
  ADD_OSQUERY_LINK_ADDITIONAL("archive")
  ADD_OSQUERY_LINK_CORE("zstd")
  ADD_OSQUERY_LINK_ADDITIONAL("zstd")
else()
  ADD_OSQUERY_LINK_CORE("zstd_static")
  ADD_OSQUERY_LINK_ADDITIONAL("archive_static")
  ADD_OSQUERY_LINK_ADDITIONAL("zstd_static")
endif()

if(APPLE)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/darwin/plist.mm"
  )

  ADD_OSQUERY_LINK(TRUE "-framework Foundation")
elseif(FREEBSD)
elseif(LINUX)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/linux/mem.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/linux/proc.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/linux/proc.h"
  )
endif()

target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/fileops.h"
      "${CMAKE_CURRENT_LIST_DIR}/filesystem.cpp"
)

if(WINDOWS)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/windows/fileops.cpp"
  )
endif()

if(POSIX)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/posix/fileops.cpp"
  )
endif()

ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_filesystem_compression
  "${CMAKE_CURRENT_LIST_DIR}/file_compression.cpp"
)

ADD_OSQUERY_TEST_CORE(
  "${CMAKE_CURRENT_LIST_DIR}/tests/fileops_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/filesystem_tests.cpp"
)

if(APPLE)
  ADD_OSQUERY_TEST_CORE(
    "${CMAKE_CURRENT_LIST_DIR}/darwin/tests/plist_tests.cpp"
  )

  ADD_OSQUERY_BENCHMARK(
    "${CMAKE_CURRENT_LIST_DIR}/darwin/benchmarks/plist_benchmarks.cpp"
  )
endif()
