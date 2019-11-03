# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryCorePluginsMain)
  generateOsqueryCorePlugins()
endfunction()

function(generateOsqueryCorePlugins)
  add_osquery_library(osquery_core_plugins EXCLUDE_FROM_ALL
    logger.cpp
    plugin.cpp
    sql_plugin.cpp
  )

  target_link_libraries(osquery_core_plugins PUBLIC
    osquery_cxx_settings

    osquery_core
    osquery_core_sql
    osquery_utils_status
  )

  target_link_libraries(osquery_core_plugins PRIVATE
    osquery_utils_json
  )

  enableLinkWholeArchive(osquery_core_plugins)

  set(public_header_files
    logger.h
    plugin.h
    sql_plugin.h
  )

  generateIncludeNamespace(osquery_core_plugins "osquery/core/plugins" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryCorePluginsMain()
