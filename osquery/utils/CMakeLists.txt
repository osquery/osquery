#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

if(NOT SKIP_AWS AND NOT WINDOWS)
  set(OSQUERY_AWS_UTIL
    "aws_util.cpp"
  )

  ADD_OSQUERY_LIBRARY_ADDITIONAL(
    osquery_aws_util
    ${OSQUERY_AWS_UTIL}
  )

  set(OSQUERY_AWS_UTIL_TESTS
    "utils/tests/aws_util_tests.cpp"
  )

  ADD_OSQUERY_TEST_ADDITIONAL(${OSQUERY_AWS_UTIL_TESTS})

  ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-core")
  ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-sts")
endif()
