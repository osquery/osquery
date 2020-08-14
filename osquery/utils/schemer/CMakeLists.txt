# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsSchemerMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  add_subdirectory("json")

  generateOsqueryUtilsSchemer()
endfunction()

function(generateOsqueryUtilsSchemer)
  add_library(osquery_utils_schemer INTERFACE)

  set(public_header_files
    schemer.h
  )

  generateIncludeNamespace(osquery_utils_schemer "osquery/utils/schemer" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_utils_schemer_tests_schemertests-test COMMAND osquery_utils_schemer_tests_schemertests-test)
endfunction()

osqueryUtilsSchemerMain()
