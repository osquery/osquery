# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryRegistryMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryRegistry()
endfunction()

function(generateOsqueryRegistry)
  add_osquery_library(osquery_registry EXCLUDE_FROM_ALL
    registry_factory.cpp
    registry_interface.cpp
  )

  target_link_libraries(osquery_registry PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_core
    osquery_process
    osquery_utils_conversions
    osquery_utils_system_env
    thirdparty_boost
  )

  add_test(NAME osquery_registry_tests-test COMMAND osquery_registry_tests-test)
endfunction()

osqueryRegistryMain()
