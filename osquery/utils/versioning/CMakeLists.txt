# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsVersioningMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryUtilsVersioningSemantic()
endfunction()

function(generateOsqueryUtilsVersioningSemantic)
  add_osquery_library(osquery_utils_versioning_semantic EXCLUDE_FROM_ALL semantic.cpp)

  target_link_libraries(osquery_utils_versioning_semantic PUBLIC
    osquery_cxx_settings
    thirdparty_boost
    osquery_utils_conversions
  )

  set(public_header_files
    semantic.h
  )

  generateIncludeNamespace(osquery_utils_versioning_semantic "osquery/utils/versioning" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_utils_versioning_semanticversiontest-test COMMAND osquery_utils_versioning_semanticversiontest-test)
endfunction()

osqueryUtilsVersioningMain()
