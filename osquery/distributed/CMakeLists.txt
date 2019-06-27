# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryDistributedMain)
  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryDistributed()
endfunction()

function(generateOsqueryDistributed)
  add_osquery_library(osquery_distributed EXCLUDE_FROM_ALL
    distributed.cpp
  )

  target_link_libraries(osquery_distributed PUBLIC
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_logger
    osquery_utils_json
    osquery_utils_system_time
  )

  add_test(NAME osquery_distributed_tests-test COMMAND osquery_distributed_tests-test)
endfunction()

osqueryDistributedMain()
