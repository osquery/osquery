# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryDistributedMain)
  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryDistributed()
endfunction()

function(generateOsqueryDistributed)
  add_osquery_library(osquery_distributed EXCLUDE_FROM_ALL
    distributed.cpp
  )

  enableLinkWholeArchive(osquery_distributed)

  target_link_libraries(osquery_distributed PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_logger
    osquery_utils_json
    osquery_utils_system_time
  )

  set(public_header_files
    distributed.h
  )

  generateIncludeNamespace(osquery_distributed "osquery/distributed" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_distributed_tests-test COMMAND osquery_distributed_tests-test)
  set(distributedtests-test_env
      "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
      "TEST_HELPER_SCRIPTS_DIR=${CMAKE_BINARY_DIR}/tools/tests"
      "OSQUERY_PYTHON_INTERPRETER_PATH=${OSQUERY_PYTHON_EXECUTABLE}"
    )

  set_tests_properties(
    osquery_distributed_tests-test
    PROPERTIES ENVIRONMENT "${distributedtests-test_env}"
  )
endfunction()

osqueryDistributedMain()
