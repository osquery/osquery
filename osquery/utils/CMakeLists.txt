#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

if(NOT SKIP_AWS)
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_aws_util
    "${CMAKE_CURRENT_LIST_DIR}/aws_util.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/aws_util.h"
  )

  if(WINDOWS)
    # This is a fix for a conversion error in the uri.hpp file of cpp-netlib
    set_source_files_properties("${CMAKE_CURRENT_LIST_DIR}/aws_util.cpp" PROPERTIES COMPILE_FLAGS "/wd4244")
  endif()

  ADD_OSQUERY_TEST_ADDITIONAL(
    "${CMAKE_CURRENT_LIST_DIR}/tests/aws_util_tests.cpp"
  )

  ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-core")
  ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-sts")
endif()
