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

function(osquery_config_plugins_main)
  generateOsqueryConfigPluginsFilesystemconfig()
  generateOsqueryConfigPluginsTlsconfig()
endfunction()

function(generateOsqueryConfigPluginsFilesystemconfig)
  add_library(osquery_config_plugins_filesystemconfig EXCLUDE_FROM_ALL
    filesystem_config.cpp
  )

  enableLinkWholeArchive(osquery_config_plugins_filesystemconfig)

  target_link_libraries(osquery_config_plugins_filesystemconfig PUBLIC
    global_cxx_settings
    osquery_config
    osquery_utils_config
  )
endfunction()

function(generateOsqueryConfigPluginsTlsconfig)
  add_library(osquery_config_plugins_tlsconfig EXCLUDE_FROM_ALL
    tls_config.cpp
  )

  enableLinkWholeArchive(osquery_config_plugins_tlsconfig)

  target_link_libraries(osquery_config_plugins_tlsconfig PUBLIC
    global_cxx_settings
    osquery_config
    osquery_remote_requests
    osquery_remote_utility
    osquery_remote_serializers_json
  )

  set(public_header_files
    tls_config.h
  )

  generateIncludeNamespace(osquery_config_plugins_tlsconfig "osquery/config/plugins" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_config_plugins_main()
