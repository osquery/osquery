# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsCachesMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryUtilsCachesLru()
endfunction()

function(generateOsqueryUtilsCachesLru)
  add_library(osquery_utils_caches_lru INTERFACE)

  set(public_header_files
    lru.h
    lru-impl.h
  )

  generateIncludeNamespace(osquery_utils_caches_lru "osquery/utils/caches" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_utils_caches_tests_lrutests-test COMMAND osquery_utils_caches_tests_lrutests-test)
endfunction()

osqueryUtilsCachesMain()
