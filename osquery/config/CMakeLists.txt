# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryConfigMain)
  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryConfig()
endfunction()

function(generateOsqueryConfig)
  add_osquery_library(osquery_config EXCLUDE_FROM_ALL
    config.cpp
    packs.cpp
  )

  enableLinkWholeArchive(osquery_config)

  target_link_libraries(osquery_config PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_filesystem
    osquery_hashing
    osquery_utils
    osquery_utils_system_time
  )

  set(public_header_files
    config.h
  )

  generateIncludeNamespace(osquery_config "osquery/config" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_config_tests-test COMMAND osquery_config_tests-test)

  add_test(NAME osquery_config_tests_packs-test COMMAND osquery_config_tests_packs-test)

  set_tests_properties(
    osquery_config_tests-test
    osquery_config_tests_packs-test
    PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
  )

endfunction()

osqueryConfigMain()
