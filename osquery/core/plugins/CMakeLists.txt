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
    sql.cpp
  )

  target_link_libraries(osquery_core_plugins PUBLIC
    global_cxx_settings
    osquery_core_sql
    osquery_utils_json
    osquery_utils_status
  )

  set(public_header_files
    logger.h
    plugin.h
    sql.h
  )

  generateIncludeNamespace(osquery_core_plugins "osquery/plugins" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryCorePluginsMain()
