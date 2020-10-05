# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

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
    osquery_cxx_settings
    osquery_core_sql
    osquery_utils_json
    osquery_utils_status
  )

  set(public_header_files
    logger.h
    plugin.h
    sql.h
  )

  generateIncludeNamespace(osquery_core_plugins "osquery/core/plugins" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryCorePluginsMain()
