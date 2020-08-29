# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsVersioningTestsMain)
  generateOsqueryUtilsVersioningTestsSemanticversiontestTest()
endfunction()

function(generateOsqueryUtilsVersioningTestsSemanticversiontestTest)
  add_osquery_executable(osquery_utils_versioning_semanticversiontest-test semantic.cpp)

  target_link_libraries(osquery_utils_versioning_semanticversiontest-test PRIVATE
    osquery_cxx_settings
    osquery_utils_versioning_semantic
    thirdparty_googletest
  )
endfunction()

osqueryUtilsVersioningTestsMain()
