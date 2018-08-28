#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# All libraries from this file will be used in main integration tests binary

# Object library for all tables integration tests
add_library(osquery_tables_integration_tests OBJECT)

#small hack for now
SET_OSQUERY_COMPILE(osquery_tables_integration_tests "${GTEST_FLAGS}")

include(${CMAKE_CURRENT_LIST_DIR}/tables/CMakeLists.txt)

target_group_sources(osquery_tables_integration_tests "${CMAKE_CURRENT_LIST_DIR}")