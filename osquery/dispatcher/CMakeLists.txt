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

function(osquery_dispatcher_main)
  generateOsqueryDispatcher()
endfunction()

function(generateOsqueryDispatcher)
  add_library(osquery_dispatcher EXCLUDE_FROM_ALL
    dispatcher.cpp
    distributed_runner.cpp
    scheduler.cpp
  )

  target_link_libraries(osquery_dispatcher PUBLIC
    global_cxx_settings
    osquery_config_parsers
    osquery_core
    osquery_process
    osquery_profiler
    osquery_sql
    osquery_logger_datalogger
    osquery_utils
    osquery_utils_conversions
    thirdparty_googletest
  )

  set(public_header_files
    distributed_runner.h
    scheduler.h
  )

  generateIncludeNamespace(osquery_dispatcher "osquery/dispatcher" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_dispatcher_main()
