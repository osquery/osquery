# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

list(APPEND CMAKE_CTEST_ARGUMENTS --output-on-failure)

if(NOT "${CMAKE_CTEST_ARGUMENTS}" MATCHES "(^|;)(-j[0-9]*|--parallel(=[0-9]+)?)(;|$)")
  include(ProcessorCount)
  ProcessorCount(test_job_count)

  if(test_job_count EQUAL 0)
    message(WARNING "Could not determine the processor count; running tests with one job")
    set(test_job_count 1)
  endif()

  list(APPEND CMAKE_CTEST_ARGUMENTS --parallel "${test_job_count}")
  configure_file("${CMAKE_CURRENT_LIST_DIR}/CTestConcurrency.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/CTestConcurrency.cmake"
    @ONLY
  )
  set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES
    "${CMAKE_CURRENT_BINARY_DIR}/CTestConcurrency.cmake"
  )
endif()
