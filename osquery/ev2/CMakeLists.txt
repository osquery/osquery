# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryEV2Main)

  if(OSQUERY_BUILD_TESTS)
    generateOsqueryEV2testsTest()
  endif()

  generateOsqueryEV2()
endfunction()

function(generateOsqueryEV2)
  set(source_files
    manager.cpp
    publisher.cpp
    subscription.cpp
  )

  add_osquery_library(osquery_ev2 EXCLUDE_FROM_ALL ${source_files})

  target_link_libraries(osquery_ev2 PUBLIC
    osquery_cxx_settings
    osquery_utils_expected
  )

  set(public_header_files
    buffered_subscription.h
    manager.h
    publisher.h
    simple_publisher.h
    subscription.h
  )

  generateIncludeNamespace(osquery_ev2 "osquery/ev2" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryEV2testsTest)
  set(source_files
    tests/buffered_subscription.cpp
    tests/manager.cpp
    tests/simple_publisher.cpp
    tests/utils.cpp
  )

  add_osquery_executable(osquery_ev2_ev2tests-test ${source_files})

  target_link_libraries(osquery_ev2_ev2tests-test PRIVATE
    osquery_cxx_settings
    osquery_ev2
    thirdparty_googletest
  )

  set(public_header_files
    tests/utils.h
  )

  generateIncludeNamespace(osquery_ev2_ev2tests-test "osquery/ev2" "FULL_PATH" ${public_header_files})

  add_test(NAME osquery_ev2_ev2tests-test COMMAND osquery_ev2_ev2tests-test)
endfunction()

osqueryEV2Main()
