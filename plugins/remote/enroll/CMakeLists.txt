# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(pluginsRemoteEnrollMain)
  generatePluginsRemoteEnrollTlsenrollplugin()
endfunction()

function(generatePluginsRemoteEnrollTlsenrollplugin)
  add_osquery_library(plugins_remote_enroll_tlsenrollplugin EXCLUDE_FROM_ALL tls_enroll_plugin.cpp)

  enableLinkWholeArchive(plugins_remote_enroll_tlsenrollplugin)

  target_link_libraries(plugins_remote_enroll_tlsenrollplugin PUBLIC
    global_cxx_settings
    osquery_remote_enroll_tlsenroll
  )
endfunction()

pluginsRemoteEnrollMain()
