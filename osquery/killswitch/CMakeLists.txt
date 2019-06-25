# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryKillswitchMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryKillswitch()
endfunction()

function(generateOsqueryKillswitch)
  add_osquery_library(osquery_killswitch EXCLUDE_FROM_ALL
    killswitch.cpp
    killswitch_plugin.cpp
    killswitch_refreshable_plugin.cpp
  )

  enableLinkWholeArchive(osquery_killswitch)

  target_link_libraries(osquery_killswitch PUBLIC
    global_cxx_settings
    osquery_core
    thirdparty_googletest_headers
  )

  set(public_header_files
    killswitch_plugin.h
    killswitch_refreshable_plugin.h
  )

  generateIncludeNamespace(osquery_killswitch "osquery/killswitch" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_killswitch_tests-test COMMAND osquery_killswitch_tests-test)

  set_tests_properties(
    osquery_killswitch_tests-test
    PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
  )
endfunction()

osqueryKillswitchMain()
