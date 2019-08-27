# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsStatusMain)

  if(BUILD_TESTING)
    generateOsqueryUtilsStatusStatustestsTest()
  endif()

  generateOsqueryUtilsStatus()
endfunction()

function(generateOsqueryUtilsStatus)
  add_osquery_library(osquery_utils_status EXCLUDE_FROM_ALL
    status.cpp
  )

  target_link_libraries(osquery_utils_status PUBLIC
    global_cxx_settings
    osquery_utils_error
    osquery_utils_expected
  )

  set(public_header_files
    status.h
  )

  generateIncludeNamespace(osquery_utils_status "osquery/utils/status" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_utils_status_statustests-test COMMAND osquery_utils_status_statustests-test)

endfunction()

function(generateOsqueryUtilsStatusStatustestsTest)
  add_osquery_executable(osquery_utils_status_statustests-test tests/status.cpp)

  target_link_libraries(osquery_utils_status_statustests-test PRIVATE
    global_cxx_settings
    osquery_utils_status
    thirdparty_googletest
  )
endfunction()

osqueryUtilsStatusMain()
