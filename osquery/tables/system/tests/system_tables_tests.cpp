/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/sql.h>

#include "osquery/core/test_util.h"

namespace osquery {
namespace tables {

QueryData genOSVersion(QueryContext& context);

class SystemsTablesTests : public testing::Test {};

TEST_F(SystemsTablesTests, test_os_version) {
  QueryContext context;
  auto result = genOSVersion(context);
  EXPECT_EQ(result.size(), 1U);

  // Make sure major and minor contain data (a missing value of -1 is an error).
  EXPECT_FALSE(result[0]["major"].empty());

// Debian does not define a minor.
#if !defined(DEBIAN)
  EXPECT_FALSE(result[0]["minor"].empty());
#endif

  // The OS name should be filled in too.
  EXPECT_FALSE(result[0]["name"].empty());
}

TEST_F(SystemsTablesTests, test_process_info) {
  auto results = SQL("select * from osquery_info join processes using (pid)");
  ASSERT_EQ(results.rows().size(), 1U);

  // Make sure there is a valid UID and parent.
  EXPECT_EQ(results.rows()[0].count("uid"), 1U);
  EXPECT_NE(results.rows()[0].at("uid"), "-1");
  EXPECT_NE(results.rows()[0].at("parent"), "-1");
}
}
}
