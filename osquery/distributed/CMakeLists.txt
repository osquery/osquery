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

function(osquery_distributed_main)
  add_subdirectory("plugins")
  generateOsqueryDistributed()
endfunction()

function(generateOsqueryDistributed)
  add_library(osquery_distributed EXCLUDE_FROM_ALL
    distributed.cpp
  )

  target_link_libraries(osquery_distributed PUBLIC
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_logger
    osquery_utils_json
    osquery_utils_system_time
  )
endfunction()

osquery_distributed_main()
