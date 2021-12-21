# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsAwsMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryUtilsAws()
endfunction()

function(generateOsqueryUtilsAws)
  add_osquery_library(osquery_utils_aws EXCLUDE_FROM_ALL
    aws_util.cpp
  )

  target_link_libraries(osquery_utils_aws PUBLIC
    osquery_cxx_settings
    osquery_remote_httpclient
    osquery_remote_transports_transportstls
    osquery_utils_json
    osquery_utils_status
    thirdparty_aws-cpp-sdk-sts
  )

  set(public_header_files
    aws_util.h
  )

  generateIncludeNamespace(osquery_utils_aws "osquery/utils/aws" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_utils_aws_tests-test COMMAND osquery_utils_aws_tests-test)

  set_tests_properties(
    osquery_utils_aws_tests-test
    PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
  )
endfunction()

osqueryUtilsAwsMain()
