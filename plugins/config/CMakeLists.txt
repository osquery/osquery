# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(pluginsConfigMain)
  add_subdirectory("parsers")

  generatePluginsConfigFilesystemconfig()
  generatePluginsConfigTlsconfig()
  generatePluginsConfigUpdateconfigplugin()
endfunction()

function(generatePluginsConfigFilesystemconfig)
  add_osquery_library(plugins_config_filesystemconfig EXCLUDE_FROM_ALL
    filesystem_config.cpp
  )

  enableLinkWholeArchive(plugins_config_filesystemconfig)

  target_link_libraries(plugins_config_filesystemconfig PUBLIC
    global_cxx_settings
    osquery_config
    osquery_utils_config
  )
endfunction()

function(generatePluginsConfigTlsconfig)
  add_osquery_library(plugins_config_tlsconfig EXCLUDE_FROM_ALL
    tls_config.cpp
  )

  enableLinkWholeArchive(plugins_config_tlsconfig)

  target_link_libraries(plugins_config_tlsconfig PUBLIC
    global_cxx_settings
    osquery_config
    osquery_remote_requests
    osquery_remote_utility
    osquery_remote_serializers_serializerjson
  )

  set(public_header_files
    tls_config.h
  )

  generateIncludeNamespace(plugins_config_tlsconfig "plugins/config" "FILE_ONLY" ${public_header_files})
endfunction()

function(generatePluginsConfigUpdateconfigplugin)
  add_osquery_library(plugins_config_updateconfigplugin EXCLUDE_FROM_ALL update.cpp)

  enableLinkWholeArchive(plugins_config_updateconfigplugin)

  target_link_libraries(plugins_config_updateconfigplugin PUBLIC
    global_cxx_settings
    osquery_config
  )
endfunction()

pluginsConfigMain()
