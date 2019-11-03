# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryConfigMain)
  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryConfig()
  generateOsqueryConfigConfigplugin()
endfunction()

function(generateOsqueryConfigConfigplugin)
  add_osquery_library(osquery_config_configplugin EXCLUDE_FROM_ALL
    config_plugin.cpp
    config_parser_plugin.cpp
  )

  enableLinkWholeArchive(osquery_config_configplugin)

  target_link_libraries(osquery_config_configplugin PUBLIC
    osquery_cxx_settings
    osquery_headers

    osquery_core
  )

  set(public_header_files
    config_plugin.h
    config_parser_plugin.h
  )

  generateIncludeNamespace(osquery_config_configplugin "osquery/config" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryConfig)
  add_osquery_library(osquery_config EXCLUDE_FROM_ALL
    config.cpp
    packs.cpp
  )

  # enableLinkWholeArchive(osquery_config)

  target_link_libraries(osquery_config PRIVATE
    osquery_cxx_settings
    osquery_headers

    osquery_config_configplugin
    osquery_dispatcher
    osquery_events
    osquery_filesystem
    osquery_hashing
    osquery_utils
    osquery_utils_system
  )

  set(public_header_files
    config.h
  )

  generateIncludeNamespace(osquery_config "osquery/config" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_config_tests-test COMMAND osquery_config_tests-test)

  set_tests_properties(
    osquery_config_tests-test
    PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
  )

endfunction()

osqueryConfigMain()
