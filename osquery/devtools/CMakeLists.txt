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

function(osquery_devtools_main)
  generateOsqueryDevtools()
endfunction()

function(generateOsqueryDevtools)
  add_library(osquery_devtools EXCLUDE_FROM_ALL
    printer.cpp
    shell.cpp
  )

  target_link_libraries(osquery_devtools PUBLIC
    global_cxx_settings
    osquery_config
    osquery_core
    osquery_filesystem
    osquery_process
    osquery_sql
    osquery_utils
    osquery_utils_conversions
    osquery_utils_system_env
    thirdparty_googletest
    thirdparty_linenoise-ng
  )

  set(public_header_files
    devtools.h
  )

  generateIncludeNamespace(osquery_devtools "osquery/devtools" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_devtools_main()
