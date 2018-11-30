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

function(osquery_remote_enroll_tlsenroll_main)
  generateOsqueryRemoteEnrollTlsenroll()
endfunction()

function(generateOsqueryRemoteEnrollTlsenroll)
  add_library(osquery_remote_enroll_tlsenroll EXCLUDE_FROM_ALL
    enroll.cpp
    tls_enroll.cpp
  )

  target_link_libraries(osquery_remote_enroll_tlsenroll PUBLIC
    global_cxx_settings
    osquery_core
    osquery_process
    osquery_remote_httpclient
    osquery_remote_requests
    osquery_remote_serializers_json
    osquery_remote_transports_tls
    osquery_utils_json
    osquery_utils_system_time
    thirdparty_boost
  )

  enableLinkWholeArchive(osquery_remote_enroll_tlsenroll)

  set(public_header_files
    tls_enroll.h
  )

  generateIncludeNamespace(osquery_remote_enroll_tlsenroll "osquery/remote/enroll" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_remote_enroll_tlsenroll_main()
