# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryCarverMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryCarver()
  generateOsqueryCarverUtils()
endfunction()

function(generateOsqueryCarver)
  add_osquery_library(osquery_carver EXCLUDE_FROM_ALL
    carver.cpp
  )

  target_link_libraries(osquery_carver PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_carver_utils
    osquery_dispatcher
    osquery_filesystem
    osquery_hashing
    osquery_remote_utility
    osquery_remote_serializers_serializerjson
    osquery_utils
    thirdparty_boost
    thirdparty_gflags
  )

  set(public_header_files
    carver.h
  )

  generateIncludeNamespace(osquery_carver "osquery/carver" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_carver_tests-test COMMAND osquery_carver_tests-test)
endfunction()


function(generateOsqueryCarverUtils)
  add_osquery_library(osquery_carver_utils EXCLUDE_FROM_ALL
    carver_utils.cpp
  )

  target_link_libraries(osquery_carver_utils PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_utils
    thirdparty_boost
    thirdparty_gflags
  )

  set(public_header_files
    carver_utils.h
  )

  generateIncludeNamespace(osquery_carver_utils "osquery/carver" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryCarverMain()
