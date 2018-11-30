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

function(osquery_carver_main)
  generateOsqueryCarver()
endfunction()

function(generateOsqueryCarver)
  add_library(osquery_carver EXCLUDE_FROM_ALL
    carver.cpp
  )

  target_link_libraries(osquery_carver PUBLIC
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_core_sql
    osquery_distributed
    osquery_filesystem
    osquery_hashing
    osquery_remote_utility
    osquery_remote_serializers_json
    osquery_utils
    thirdparty_boost
    thirdparty_gflags
  )

  set(public_header_files
    carver.h
  )

  generateIncludeNamespace(osquery_carver "osquery/carver" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_carver_main()
