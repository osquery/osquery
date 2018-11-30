# Copyright (c) 2018-present, Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13.1)

function(osquery_remote_main)
  add_subdirectory("serializers")
  add_subdirectory("transports")
  add_subdirectory("enroll")

  generateOsqueryRemoteRequests()
  generateOsqueryRemoteHttpclient()
  generateOsqueryRemoteUtility()
endfunction()

function(generateOsqueryRemoteRequests)
  add_library(osquery_remote_requests EXCLUDE_FROM_ALL
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
  add_library(osquery_remote_httpclient EXCLUDE_FROM_ALL
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
  add_library(osquery_remote_utility INTERFACE)

  target_link_libraries(osquery_remote_utility INTERFACE
    global_cxx_settings
    osquery_process
    osquery_remote_transports_tls
    osquery_remote_httpclient
    osquery_remote_requests
  )

  set(public_header_files
    utility.h
  )

  generateIncludeNamespace(osquery_remote_utility "osquery/remote" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_remote_main()
