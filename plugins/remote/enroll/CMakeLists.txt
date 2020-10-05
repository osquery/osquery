# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(pluginsRemoteEnrollMain)
  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generatePluginsRemoteEnrollTlsenroll()
endfunction()

function(generatePluginsRemoteEnrollTlsenroll)
  add_osquery_library(plugins_remote_enroll_tlsenroll EXCLUDE_FROM_ALL
    tls_enroll.cpp
  )

  enableLinkWholeArchive(plugins_remote_enroll_tlsenroll)

  target_link_libraries(plugins_remote_enroll_tlsenroll PUBLIC
    osquery_cxx_settings
    osquery_remote_enroll_tlsenroll
  )

  set(public_header_files
    tls_enroll.h
  )

  generateIncludeNamespace(plugins_remote_enroll_tlsenroll "plugins/remote/enroll" "FILE_ONLY" ${public_header_files})

  add_test(NAME plugins_remote_enroll_tlsenrolltests-test COMMAND plugins_remote_enroll_tlsenrolltests-test)

  set(tlsenrolltests-test_env
    "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
    "TEST_HELPER_SCRIPTS_DIR=${CMAKE_BINARY_DIR}/tools/tests"
    "OSQUERY_PYTHON_INTERPRETER_PATH=${OSQUERY_PYTHON_EXECUTABLE}"
  )

  set_tests_properties(
    plugins_remote_enroll_tlsenrolltests-test
    PROPERTIES ENVIRONMENT "${tlsenrolltests-test_env}"
  )

endfunction()

pluginsRemoteEnrollMain()
