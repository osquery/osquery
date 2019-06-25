# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(pluginsConfigParsersTestsMain)
  generatePluginsConfigParsersTestsDecoratorstestsTest()
  generatePluginsConfigParsersTestsEventsparsertestsTest()
  generatePluginsConfigParsersTestsFilepathstestsTest()
  generatePluginsConfigParsersTestsOptionstestsTest()
  generatePluginsConfigParsersTestsViewstestsTest()
endfunction()

function(generatePluginsConfigParsersTestsDecoratorstestsTest)
  add_osquery_executable(plugins_config_parsers_tests_decoratorstests-test decorators_tests.cpp)

  target_link_libraries(plugins_config_parsers_tests_decoratorstests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_database
    osquery_dispatcher
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_json
    plugins_config_tlsconfig
    plugins_config_parsers
    plugins_database_ephemeral
    specs_tables
    osquery_tools_tests_conffiles
    thirdparty_googletest
  )
endfunction()

function(generatePluginsConfigParsersTestsEventsparsertestsTest)

  add_osquery_executable(plugins_config_parsers_tests_eventsparsertests-test events_parser_tests.cpp)

  target_link_libraries(plugins_config_parsers_tests_eventsparsertests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_database
    osquery_dispatcher
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_json
    plugins_config_tlsconfig
    plugins_config_parsers
    plugins_database_ephemeral
    specs_tables
    osquery_tools_tests_conffiles
    thirdparty_googletest
  )

endfunction()

function(generatePluginsConfigParsersTestsFilepathstestsTest)
  add_osquery_executable(plugins_config_parsers_tests_filepathstests-test file_paths_tests.cpp)

  target_link_libraries(plugins_config_parsers_tests_filepathstests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_database
    osquery_dispatcher
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_json
    plugins_config_tlsconfig
    plugins_config_parsers
    plugins_database_ephemeral
    specs_tables
    osquery_tools_tests_conffiles
    thirdparty_googletest
  )
endfunction()

function(generatePluginsConfigParsersTestsOptionstestsTest)

  add_osquery_executable(plugins_config_parsers_tests_optionstests-test options_tests.cpp)

  target_link_libraries(plugins_config_parsers_tests_optionstests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_database
    osquery_dispatcher
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_json
    plugins_config_tlsconfig
    plugins_config_parsers
    plugins_database_ephemeral
    specs_tables
    osquery_tools_tests_conffiles
    thirdparty_googletest
  )
endfunction()

function(generatePluginsConfigParsersTestsViewstestsTest)
  add_osquery_executable(plugins_config_parsers_tests_viewstests-test views_tests.cpp)

  target_link_libraries(plugins_config_parsers_tests_viewstests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_database
    osquery_dispatcher
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_json
    plugins_config_tlsconfig
    plugins_config_parsers
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

pluginsConfigParsersTestsMain()
