/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/system.h>
#include <osquery/registry/registry_interface.h>
#include <osquery/sql/sql.h>

#include <gtest/gtest.h>

namespace osquery {
class SQLiteNetworkTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
  }
};

TEST_F(SQLiteNetworkTests, test_in_cidr_block) {
  Row r;
  r["result"] = "1";

  SQL sql = SQL("SELECT in_cidr_block('10.0.0.0/26', '10.0.0.24') AS result;");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  sql = SQL(
      "SELECT in_cidr_block('198.51.100.14/24', '198.51.100.14') AS result;");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  sql =
      SQL("SELECT in_cidr_block('2a00:a040:019e:f12a:0000:0000:0000:0000/64',"
          "'2a00:a040:19e:f12a:658b:3589:b2ba:71a3') AS result;");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  sql =
      SQL("SELECT in_cidr_block('2001:db8::/48',"
          "'2001:db8:0:ffff:ffff:ffff:ffff:ffff') AS result;");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);
}
} // namespace osquery
