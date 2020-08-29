# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(pluginsConfigMain)
  add_subdirectory("parsers")
  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generatePluginsConfigFilesystemconfig()
  generatePluginsConfigTlsconfig()
  generatePluginsConfigUpdateconfigplugin()
endfunction()

function(generatePluginsConfigFilesystemconfig)
  add_osquery_library(plugins_config_filesystemconfig EXCLUDE_FROM_ALL
    filesystem_config.cpp
  )

  enableLinkWholeArchive(plugins_config_filesystemconfig)

  target_link_libraries(plugins_config_filesystemconfig PUBLIC
    osquery_cxx_settings
    osquery_config
    osquery_utils_config
  )
endfunction()

function(generatePluginsConfigTlsconfig)
  add_osquery_library(plugins_config_tlsconfig EXCLUDE_FROM_ALL
    tls_config.cpp
  )

  enableLinkWholeArchive(plugins_config_tlsconfig)

  target_link_libraries(plugins_config_tlsconfig PUBLIC
    osquery_cxx_settings
    osquery_config
    osquery_remote_requests
    osquery_remote_utility
    osquery_remote_serializers_serializerjson
  )

  set(public_header_files
    tls_config.h
  )

  generateIncludeNamespace(plugins_config_tlsconfig "plugins/config" "FILE_ONLY" ${public_header_files})

  add_test(NAME plugins_config_tests_tlsconfigtests-test COMMAND plugins_config_tests_tlsconfigtests-test)

  set(tlsconfigtests-test_env
    "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
    "TEST_HELPER_SCRIPTS_DIR=${CMAKE_BINARY_DIR}/tools/tests"
    "OSQUERY_PYTHON_INTERPRETER_PATH=${OSQUERY_PYTHON_EXECUTABLE}"
  )

  set_tests_properties(
    plugins_config_tests_tlsconfigtests-test
    PROPERTIES ENVIRONMENT "${tlsconfigtests-test_env}"
  )

endfunction()

function(generatePluginsConfigUpdateconfigplugin)
  add_osquery_library(plugins_config_updateconfigplugin EXCLUDE_FROM_ALL update.cpp)

  enableLinkWholeArchive(plugins_config_updateconfigplugin)

  target_link_libraries(plugins_config_updateconfigplugin PUBLIC
    osquery_cxx_settings
    osquery_config
  )
endfunction()

pluginsConfigMain()
