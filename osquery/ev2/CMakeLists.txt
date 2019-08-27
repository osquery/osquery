# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryEV2Main)

  if(BUILD_TESTING)
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
    global_cxx_settings
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
    global_cxx_settings
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
