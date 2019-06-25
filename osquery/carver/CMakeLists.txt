# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryCarverMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryCarver()
endfunction()

function(generateOsqueryCarver)
  add_osquery_library(osquery_carver EXCLUDE_FROM_ALL
    carver.cpp
  )

  target_link_libraries(osquery_carver PUBLIC
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_core_sql
    osquery_distributed
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

osqueryCarverMain()
