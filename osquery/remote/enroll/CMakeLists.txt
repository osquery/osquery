# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryRemoteEnrollTlsenrollMain)
  if(BUILD_TESTING)
    generateOsqueryRemoteenrolltestsTest()
  endif()

  generateOsqueryRemoteEnrollTlsenroll()
endfunction()

function(generateOsqueryRemoteEnrollTlsenroll)
  add_osquery_library(osquery_remote_enroll_tlsenroll EXCLUDE_FROM_ALL
    enroll.cpp
    tls_enroll.cpp
  )

  target_link_libraries(osquery_remote_enroll_tlsenroll PUBLIC
    global_cxx_settings
    osquery_core
    osquery_process
    osquery_remote_httpclient
    osquery_remote_requests
    osquery_remote_serializers_serializerjson
    osquery_remote_transports_transportstls
    osquery_utils_json
    osquery_utils_system_time
    thirdparty_boost
  )

  enableLinkWholeArchive(osquery_remote_enroll_tlsenroll)

  set(public_header_files
    tls_enroll.h
  )

  generateIncludeNamespace(osquery_remote_enroll_tlsenroll "osquery/remote/enroll" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_remote_enroll_remoteenrolltests-test COMMAND osquery_remote_enroll_remoteenrolltests-test)

  set_tests_properties(
    osquery_remote_enroll_remoteenrolltests-test
    PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
  )
endfunction()

function(generateOsqueryRemoteenrolltestsTest)

  set(source_files
    tests/enroll_tests.cpp
  )

  if(DEFINED PLATFORM_MACOS)
    list(APPEND source_files tests/plugins/tls_enroll_tests.cpp)
  endif()

  add_osquery_executable(osquery_remote_enroll_remoteenrolltests-test ${source_files})

  target_link_libraries(osquery_remote_enroll_remoteenrolltests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_process
    osquery_remote_enroll_tlsenroll
    osquery_remote_tests_remotetestutils
    osquery_utils_conversions
    osquery_utils_info
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_killswitch_killswitchfilesystem
    tests_helper
    thirdparty_googletest
    osquery_tools_tests_testfiles
  )
endfunction()

osqueryRemoteEnrollTlsenrollMain()
