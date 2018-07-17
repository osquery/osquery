#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_carver
  "${CMAKE_CURRENT_LIST_DIR}/carver.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/carver.h"
)

ADD_OSQUERY_TEST(FALSE 
  "${CMAKE_CURRENT_LIST_DIR}/tests/carver_tests.cpp"
)
