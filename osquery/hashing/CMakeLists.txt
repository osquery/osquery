# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryHashingMain)
  generateOsqueryHashing()
endfunction()

function(generateOsqueryHashing)
  add_osquery_library(osquery_hashing EXCLUDE_FROM_ALL
    hashing.cpp
  )

  target_link_libraries(osquery_hashing PUBLIC
    osquery_cxx_settings
    osquery_filesystem
    osquery_utils
    osquery_utils_info
    thirdparty_openssl
  )

  set(public_header_files
    hashing.h
  )

  generateIncludeNamespace(osquery_hashing "osquery/hashing" "FILE_ONLY" ${public_header_files})

  if(OSQUERY_BUILD_TESTS)
    generateOsqueryHashingTestsTest()
  endif()

  add_test(NAME osquery_hashing_tests-test COMMAND osquery_hashing_tests-test)
endfunction()

function(generateOsqueryHashingTestsTest)
  set(source_files
    tests/hashing.cpp
  )

  add_osquery_executable(osquery_hashing_tests-test ${source_files})

  target_link_libraries(osquery_hashing_tests-test PRIVATE
    osquery_cxx_settings
    osquery_hashing
    osquery_filesystem
    osquery_extensions
    osquery_extensions_implthrift
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryHashingMain()
