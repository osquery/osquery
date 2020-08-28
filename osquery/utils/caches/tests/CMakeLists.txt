# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsCachesTestsLrutestsMain)
  generateOsqueryUtilsCachesTestsLrutestsTest()
endfunction()

function(generateOsqueryUtilsCachesTestsLrutestsTest)
  add_osquery_executable(osquery_utils_caches_tests_lrutests-test lru.cpp)

  target_link_libraries(osquery_utils_caches_tests_lrutests-test PUBLIC
    osquery_cxx_settings
    osquery_utils_caches_lru
    thirdparty_googletest
  )
endfunction()

osqueryUtilsCachesTestsLrutestsMain()
