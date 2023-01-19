# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(pluginsDistributedMain)
  generatePluginsDistributedTls()
endfunction()

function(generatePluginsDistributedTls)
  add_osquery_library(plugins_distributed_tls_distributedtls EXCLUDE_FROM_ALL
    tls_distributed.cpp
  )

  enableLinkWholeArchive(plugins_distributed_tls_distributedtls)

  target_link_libraries(plugins_distributed_tls_distributedtls PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_config
    osquery_database
    osquery_distributed
    osquery_logger
    osquery_remote_utility
    osquery_remote_serializers_serializerjson
    osquery_utils_json
  )
endfunction()

pluginsDistributedMain()
