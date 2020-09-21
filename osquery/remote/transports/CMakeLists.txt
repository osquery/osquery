# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryRemoteTransportsMain)

  if(OSQUERY_BUILD_TESTS AND DEFINED PLATFORM_POSIX)
    generateOsqueryRemoteTransportsRemotetransportstlstestsTest()
  endif()

  generateOsqueryRemoteTransportsTransportstls()
endfunction()

function(generateOsqueryRemoteTransportsTransportstls)
  add_osquery_library(osquery_remote_transports_transportstls EXCLUDE_FROM_ALL
    tls.cpp
  )

  target_link_libraries(osquery_remote_transports_transportstls PUBLIC
    osquery_cxx_settings
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

    set(remotetransportstlstests-test_env
      "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
      "TEST_HELPER_SCRIPTS_DIR=${CMAKE_BINARY_DIR}/tools/tests"
      "OSQUERY_PYTHON_INTERPRETER_PATH=${OSQUERY_PYTHON_EXECUTABLE}"
    )

    set_tests_properties(
      osquery_remote_transports_remotetransportstlstests-test
      PROPERTIES ENVIRONMENT "${remotetransportstlstests-test_env}"
    )
  endif()
endfunction()


function(generateOsqueryRemoteTransportsRemotetransportstlstestsTest)

  add_osquery_executable(osquery_remote_transports_remotetransportstlstests-test tests/tls_transports_tests.cpp)

  target_link_libraries(osquery_remote_transports_remotetransportstlstests-test PRIVATE
    osquery_cxx_settings
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
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryRemoteTransportsMain()
