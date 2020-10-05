# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryRemoteEnrollTlsenrollMain)
  if(OSQUERY_BUILD_TESTS)
    generateOsqueryRemoteenrolltestsTest()
  endif()

  generateOsqueryRemoteEnrollTlsenroll()
endfunction()

function(generateOsqueryRemoteEnrollTlsenroll)
  add_osquery_library(osquery_remote_enroll_tlsenroll EXCLUDE_FROM_ALL
    enroll.cpp
  )

  target_link_libraries(osquery_remote_enroll_tlsenroll PUBLIC
    osquery_cxx_settings
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
    enroll.h
  )

  generateIncludeNamespace(osquery_remote_enroll_tlsenroll "osquery/remote/enroll" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_remote_enroll_remoteenrolltests-test COMMAND osquery_remote_enroll_remoteenrolltests-test)

  set(remoteenrolltests-test_env
    "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
    "TEST_HELPER_SCRIPTS_DIR=${CMAKE_BINARY_DIR}/tools/tests"
    "OSQUERY_PYTHON_INTERPRETER_PATH=${OSQUERY_PYTHON_EXECUTABLE}"
  )

  set_tests_properties(
    osquery_remote_enroll_remoteenrolltests-test
    PROPERTIES ENVIRONMENT "${remoteenrolltests-test_env}"
  )
endfunction()

function(generateOsqueryRemoteenrolltestsTest)

  set(source_files
    tests/enroll_tests.cpp
  )

  add_osquery_executable(osquery_remote_enroll_remoteenrolltests-test ${source_files})

  target_link_libraries(osquery_remote_enroll_remoteenrolltests-test PRIVATE
    osquery_cxx_settings
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
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryRemoteEnrollTlsenrollMain()
