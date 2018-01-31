#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

if(NOT SKIP_AWS)
  set(OSQUERY_AWS_UTIL
    "aws_util.cpp"
  )

  if(WINDOWS)
    # This is a fix for a conversion error in the uri.hpp file of cpp-netlib
    set_source_files_properties("aws_util.cpp" PROPERTIES COMPILE_FLAGS "/wd4244")
  endif()

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
