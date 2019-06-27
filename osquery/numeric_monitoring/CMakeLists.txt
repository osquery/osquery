# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryNumericmonitoringMain)
  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryNumericmonitoring()
endfunction()

function(generateOsqueryNumericmonitoring)
  add_osquery_library(osquery_numericmonitoring EXCLUDE_FROM_ALL
    numeric_monitoring.cpp
    plugin_interface.cpp
    pre_aggregation_cache.cpp
  )

  target_link_libraries(osquery_numericmonitoring PUBLIC
    global_cxx_settings
    osquery_core
    osquery_utils
    thirdparty_boost
  )

  set(public_header_files
    plugin_interface.h
    pre_aggregation_cache.h
  )

  generateIncludeNamespace(osquery_numericmonitoring "osquery/numeric_monitoring" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_numericmonitoring_tests-test COMMAND osquery_numericmonitoring_tests-test)
  add_test(NAME osquery_numericmonitoring_tests_preaggregationcache-test COMMAND osquery_numericmonitoring_tests_preaggregationcache-test)
endfunction()

osqueryNumericmonitoringMain()
