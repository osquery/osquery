# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryRemoteMain)
  add_subdirectory("serializers")
  add_subdirectory("transports")
  add_subdirectory("enroll")

  if(OSQUERY_BUILD_TESTS)
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
    osquery_cxx_settings
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
    osquery_cxx_settings
    osquery_logger
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
    osquery_cxx_settings
    osquery_process
    osquery_remote_transports_transportstls
    osquery_remote_httpclient
    osquery_remote_requests
    plugins_remote_enroll_tlsenroll
  )

  set(public_header_files
    utility.h
  )

  generateIncludeNamespace(osquery_remote_utility "osquery/remote" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_remote_tests_requeststests-test COMMAND osquery_remote_tests_requeststests-test)
endfunction()

osqueryRemoteMain()
