# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(pluginsDistributedMain)
  generatePluginsDistributedTls()
endfunction()

function(generatePluginsDistributedTls)
  add_osquery_library(plugins_distributed_tls_distributedtls EXCLUDE_FROM_ALL
    tls_distributed.cpp
  )

  enableLinkWholeArchive(plugins_distributed_tls_distributedtls)

  target_link_libraries(plugins_distributed_tls_distributedtls PUBLIC
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_logger
    osquery_remote_utility
    osquery_remote_serializers_serializerjson
    osquery_utils_json
  )
endfunction()

pluginsDistributedMain()
