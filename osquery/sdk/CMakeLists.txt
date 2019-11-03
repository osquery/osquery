# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osquerySdkMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsquerySdk()
endfunction()

function(generateOsquerySdk)
  add_osquery_library(osquery_sdk EXCLUDE_FROM_ALL
    sql_plugin_external.cpp
    empty_register_foreign_tables.cpp
  )

  target_link_libraries(osquery_sdk PUBLIC
    osquery_headers
    osquery_config
    osquery_core_plugins
    osquery_experimental_eventsstream_registry
    osquery_extensions
    osquery_numericmonitoring
    osquery_sql
    osquery_utils
    osquery_utils_debug
    osquery_utils_system
    plugins_database_ephemeral
  )

  enableLinkWholeArchive(osquery_sdk)

  set(public_headers
    sdk.h
  )

  generateIncludeNamespace(osquery_sdk "osquery/sdk" "FILE_ONLY" ${public_headers})

  add_test(NAME osquery_sdk_tests_pluginsdktests-test COMMAND osquery_sdk_tests_pluginsdktests-test)
endfunction()

osquerySdkMain()
