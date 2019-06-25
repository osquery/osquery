# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryRemoteMain)
  add_subdirectory("serializers")
  add_subdirectory("transports")
  add_subdirectory("enroll")

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryRemoteRequests()
  generateOsqueryRemoteHttpclient()
  generateOsqueryRemoteUtility()
endfunction()

function(generateOsqueryRemoteRequests)
  add_osquery_library(osquery_remote_requests EXCLUDE_FROM_ALL
    requests.cpp
  )

  target_link_libraries(osquery_remote_requests PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_utils_status
    thirdparty_boost
    thirdparty_openssl
    thirdparty_zlib
  )

  set(public_header_files
    requests.h
  )

  generateIncludeNamespace(osquery_remote_requests "osquery/remote" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryRemoteHttpclient)
  add_osquery_library(osquery_remote_httpclient EXCLUDE_FROM_ALL
    http_client.cpp
    uri.cpp
  )

  target_link_libraries(osquery_remote_httpclient PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_utils_status
    thirdparty_boost
    thirdparty_openssl
  )

  set(public_header_files
    http_client.h
    uri.h
  )

  generateIncludeNamespace(osquery_remote_httpclient "osquery/remote" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryRemoteUtility)
  add_osquery_library(osquery_remote_utility INTERFACE)

  target_link_libraries(osquery_remote_utility INTERFACE
    global_cxx_settings
    osquery_process
    osquery_remote_transports_transportstls
    osquery_remote_httpclient
    osquery_remote_requests
  )

  set(public_header_files
    utility.h
  )

  generateIncludeNamespace(osquery_remote_utility "osquery/remote" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_remote_tests_requeststests-test COMMAND osquery_remote_tests_requeststests-test)
endfunction()

osqueryRemoteMain()
