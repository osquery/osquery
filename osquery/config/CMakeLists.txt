# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryConfigMain)
  if(OSQUERY_BUILD_TESTS)
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
    osquery_cxx_settings
    osquery_events_eventsregistry
    osquery_filesystem
    osquery_hashing
    osquery_registry
    osquery_utils
    osquery_utils_system_time
  )

  set(public_header_files
    config.h
    packs.h
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
