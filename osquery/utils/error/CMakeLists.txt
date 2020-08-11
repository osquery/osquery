# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsErrorMain)

  if(OSQUERY_BUILD_TESTS)
    generateOsqueryUtilsErrorErrortestsTest()
  endif()

  generateOsqueryUtilsError()
endfunction()

function(generateOsqueryUtilsError)
  add_osquery_library(osquery_utils_error INTERFACE)

  target_link_libraries(osquery_utils_error INTERFACE
    osquery_cxx_settings
    osquery_utils_conversions_to
    osquery_utils_attribute
  )

  set(public_header_files
    error.h
  )

  generateIncludeNamespace(osquery_utils_error "osquery/utils/error" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_utils_error_errortests-test COMMAND osquery_utils_error_errortests-test)

endfunction()

function(generateOsqueryUtilsErrorErrortestsTest)
  add_osquery_executable(osquery_utils_error_errortests-test tests/error.cpp)

  target_link_libraries(osquery_utils_error_errortests-test PRIVATE
    osquery_cxx_settings
    osquery_utils_error
    thirdparty_googletest
  )
endfunction()

osqueryUtilsErrorMain()
