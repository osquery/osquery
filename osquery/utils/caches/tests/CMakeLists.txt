# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsCachesTestsLrutestsMain)
  generateOsqueryUtilsCachesTestsLrutestsTest()
endfunction()

function(generateOsqueryUtilsCachesTestsLrutestsTest)
  add_osquery_executable(osquery_utils_caches_tests_lrutests-test lru.cpp)

  target_link_libraries(osquery_utils_caches_tests_lrutests-test PUBLIC
    global_cxx_settings
    osquery_utils_caches_lru
    thirdparty_googletest
  )
endfunction()

osqueryUtilsCachesTestsLrutestsMain()
