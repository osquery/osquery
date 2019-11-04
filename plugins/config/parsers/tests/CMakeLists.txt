# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(pluginsConfigParsersTestsMain)
  generatePluginsConfigParsersTests()
endfunction()

function(generatePluginsConfigParsersTests)
  add_osquery_executable(plugins_config_parsers_tests-test
    decorators_tests.cpp
    events_parser_tests.cpp
    file_paths_tests.cpp
    options_tests.cpp
    views_tests.cpp
  )

  target_link_libraries(plugins_config_parsers_tests-test PRIVATE
    osquery_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_database
#    osquery_dispatcher
    osquery_events
#    osquery_extensions
#    osquery_extensions
    osquery_filesystem
    osquery_registry
#    osquery_remote_enroll_tlsenroll
    osquery_utils_json
#    plugins_config_tlsconfig
    plugins_config_parsers
    plugins_database_ephemeral
    specs_tables
    osquery_tools_tests_conffiles
    thirdparty_googletest
  )
endfunction()

pluginsConfigParsersTestsMain()
