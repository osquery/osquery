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

function(osquery_kilswitch_main)
  add_subdirectory("plugins")
  generateOsqueryKillswitch()
endfunction()

function(generateOsqueryKillswitch)
  add_library(osquery_killswitch EXCLUDE_FROM_ALL
    killswitch.cpp
    killswitch_plugin.cpp
    killswitch_refreshable_plugin.cpp
  )

  enableLinkWholeArchive(osquery_killswitch)

  target_link_libraries(osquery_killswitch PUBLIC
    global_cxx_settings
    osquery_core
    thirdparty_googletest
  )

  set(public_header_files
    killswitch_plugin.h
    killswitch_refreshable_plugin.h
  )

  generateIncludeNamespace(osquery_killswitch "osquery/killswitch" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_kilswitch_main()
