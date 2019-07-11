/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/sql/query_data.h>

namespace osquery {
namespace tables {

class PlatformTableTest : public testing::Test {};

TEST_F(PlatformTableTest, test_platform_table) {
  SQL results("select * from osquery_platform");
  ASSERT_EQ(results.rows().size(), 1U);
  EXPECT_EQ(rows[0].at("posix"), 1);
  EXPECT_EQ(rows[0].at("windows"), 0);
  EXPECT_EQ(rows[0].at("bsd"), 0);
  EXPECT_EQ(rows[0].at("linux"), 1);
  EXPECT_EQ(rows[0].at("osx"), 0);
  EXPECT_EQ(rows[0].at("freebsd"), 0);
}
} // namespace tables
} // namespace osquery
