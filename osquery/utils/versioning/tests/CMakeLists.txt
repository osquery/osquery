# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsVersioningTestsMain)
  generateOsqueryUtilsVersioningTestsSemanticversiontestTest()
endfunction()

function(generateOsqueryUtilsVersioningTestsSemanticversiontestTest)
  add_osquery_executable(osquery_utils_versioning_semanticversiontest-test semantic.cpp)

  target_link_libraries(osquery_utils_versioning_semanticversiontest-test PRIVATE
    global_cxx_settings
    osquery_utils_versioning_semantic
    thirdparty_googletest
  )
endfunction()

osqueryUtilsVersioningTestsMain()
