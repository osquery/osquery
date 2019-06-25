# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsDebugMain)

  if(BUILD_TESTING)
    generateOsqueryUtilsDebugDebugtestsTest()
  endif()

  generateOsqueryUtilsDebug()
endfunction()

function(generateOsqueryUtilsDebug)
  add_osquery_library(osquery_utils_debug INTERFACE)

  target_link_libraries(osquery_utils_debug INTERFACE
    global_cxx_settings
    thirdparty_boost
  )

  set(public_header_files
    debug_only.h
  )

  generateIncludeNamespace(osquery_utils_debug "osquery/utils/debug" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_utils_debug_debugtests-test COMMAND osquery_utils_debug_debugtests-test)

endfunction()

function(generateOsqueryUtilsDebugDebugtestsTest)
  add_osquery_executable(osquery_utils_debug_debugtests-test tests/debug_only.cpp)

  target_link_libraries(osquery_utils_debug_debugtests-test PRIVATE
    global_cxx_settings
    osquery_utils_debug
    thirdparty_googletest
  )
endfunction()

osqueryUtilsDebugMain()
