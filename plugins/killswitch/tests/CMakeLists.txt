# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(pluginsKillswitchTestsMain)
  generatePluginsKillswitchTestsKillswitchfilesystemplugintestsTest()
endfunction()

function(generatePluginsKillswitchTestsKillswitchfilesystemplugintestsTest)
  add_osquery_executable(plugins_killswitch_killswitchfilesystemplugintests-test killswitch_filesystem_tests.cpp)

  target_link_libraries(plugins_killswitch_killswitchfilesystemplugintests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_info
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_killswitch_killswitchfilesystem
    tests_helper
    osquery_tools_tests_conffiles
    thirdparty_googletest
  )
endfunction()

pluginsKillswitchTestsMain()
