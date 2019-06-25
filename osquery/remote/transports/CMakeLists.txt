# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryRemoteTransportsMain)

  if(BUILD_TESTING AND DEFINED PLATFORM_POSIX)
    generateOsqueryRemoteTransportsRemotetransportstlstestsTest()
  endif()

  generateOsqueryRemoteTransportsTransportstls()
endfunction()

function(generateOsqueryRemoteTransportsTransportstls)
  add_osquery_library(osquery_remote_transports_transportstls EXCLUDE_FROM_ALL
    tls.cpp
  )

  target_link_libraries(osquery_remote_transports_transportstls PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_core
    osquery_remote_httpclient
    osquery_remote_requests
    osquery_utils_json
    thirdparty_boost
  )

  set(public_header_files
    tls.h
  )

  generateIncludeNamespace(osquery_remote_transports_transportstls "osquery/remote/transports" "FILE_ONLY" ${public_header_files})

  if(DEFINED PLATFORM_POSIX)
    add_test(NAME osquery_remote_transports_remotetransportstlstests-test COMMAND osquery_remote_transports_remotetransportstlstests-test)

    set_tests_properties(
      osquery_remote_transports_remotetransportstlstests-test
      PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
    )
  endif()
endfunction()


function(generateOsqueryRemoteTransportsRemotetransportstlstestsTest)

  add_osquery_executable(osquery_remote_transports_remotetransportstlstests-test tests/tls_transports_tests.cpp)

  target_link_libraries(osquery_remote_transports_remotetransportstlstests-test PRIVATE
    global_cxx_settings
    osquery_config_tests_testutils
    osquery_database
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
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

osqueryRemoteTransportsMain()
