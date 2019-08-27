# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(pluginsKillswitchMain)
  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generatePluginsKillswitchKillswitchfilesystem()
  generatePluginsKillswitchTls()
endfunction()

function(generatePluginsKillswitchKillswitchfilesystem)
  add_osquery_library(plugins_killswitch_killswitchfilesystem EXCLUDE_FROM_ALL
    killswitch_filesystem.cpp
  )

  enableLinkWholeArchive(plugins_killswitch_killswitchfilesystem)

  target_link_libraries(plugins_killswitch_killswitchfilesystem PUBLIC
    global_cxx_settings
    osquery_killswitch
    osquery_utils_config
  )

  set(public_header_files
    killswitch_filesystem.h
  )

  generateIncludeNamespace(plugins_killswitch_killswitchfilesystem "osquery/killswitch/plugins" "FILE_ONLY" ${public_header_files})

  add_test(NAME plugins_killswitch_killswitchfilesystemplugintests-test COMMAND plugins_killswitch_killswitchfilesystemplugintests-test)

  set_tests_properties(
    plugins_killswitch_killswitchfilesystemplugintests-test
    PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
  )
endfunction()

function(generatePluginsKillswitchTls)
  add_osquery_library(plugins_killswitch_killswitchtls EXCLUDE_FROM_ALL
    killswitch_tls.cpp
  )

  enableLinkWholeArchive(plugins_killswitch_killswitchtls)

  target_link_libraries(plugins_killswitch_killswitchtls PUBLIC
    global_cxx_settings
    osquery_killswitch
    osquery_remote_utility
    osquery_remote_serializers_serializerjson
  )

  set(public_header_files
    killswitch_tls.h
  )

  generateIncludeNamespace(plugins_killswitch_killswitchtls "osquery/killswitch/plugins" "FILE_ONLY" ${public_header_files})
endfunction()

pluginsKillswitchMain()
