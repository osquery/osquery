# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsSchemerMain)

  if(BUILD_TESTING)
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
