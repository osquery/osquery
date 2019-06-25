# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osquerySdkMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsquerySdkPluginsdk()
endfunction()

function(generateOsquerySdkPluginsdk)
  add_osquery_library(osquery_sdk_pluginsdk EXCLUDE_FROM_ALL empty_register_foreign_tables.cpp)

  target_link_libraries(osquery_sdk_pluginsdk INTERFACE
    osquery_headers
    osquery_config
    osquery_dispatcher
    osquery_events_eventsregistry
    osquery_experimental_eventsstream_registry
    osquery_extensions
    osquery_killswitch
    osquery_numericmonitoring
    osquery_remote_enroll_tlsenroll
    osquery_sql
    osquery_utils_conversions
    osquery_utils_debug
    osquery_utils_expected
    osquery_utils_info
    osquery_utils_macros
    osquery_utils_status
    osquery_utils_system_env
    osquery_utils_system_errno
    osquery_utils_system_filepath
    osquery_utils_system_systemutils
    osquery_utils_system_time
    osquery_utils_system_uptime
    osquery_utils_attribute
    osquery_utils
    plugins_database_ephemeral
  )

  enableLinkWholeArchive(osquery_sdk_pluginsdk)

  set(public_headers
    plugin_sdk.h
    sdk.h
  )

  generateIncludeNamespace(osquery_sdk_pluginsdk "osquery/sdk" "FILE_ONLY" ${public_headers})

  add_test(NAME osquery_sdk_tests_pluginsdktests-test COMMAND osquery_sdk_tests_pluginsdktests-test)
endfunction()

osquerySdkMain()
