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
class SQLiteHashingTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
  }
};

TEST_F(SQLiteHashingTests, test_community_id_v1_tcp) {
  Row r;
  r["hash"] = "1:LQU9qZlK+B5F3KDmev6m5PMibrg=";

  SQL sql =
      SQL("SELECT community_id_v1('66.35.250.204', '128.232.110.120', 80, "
          "34855, 6, 0) AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  sql =
      SQL("SELECT community_id_v1('128.232.110.120', '66.35.250.204', 34855, "
          "80, 6) AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  r["hash"] = "1:3V71V58M3Ksw/yuFALMcW0LAHvc=";

  sql =
      SQL("SELECT community_id_v1('66.35.250.204', '128.232.110.120', 80, "
          "34855, 6, 1) AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  sql =
      SQL("SELECT community_id_v1('128.232.110.120', '66.35.250.204', 34855, "
          "80, 6, 1) AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  r["hash"] = "1:Jww+Ua4pSUNl9TvSUwvSHL4n93w=";

  sql =
      SQL("SELECT community_id_v1('127.0.0.1', 'fe80::14b0:de4a:f8e8:522f', "
          "64, 10, 6) AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  sql =
      SQL("SELECT community_id_v1('fe80::14b0:de4a:f8e8:522f', '127.0.0.1', "
          "10, 64, 6, 0) AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);
}

TEST_F(SQLiteHashingTests, test_community_id_v1_sctp) {
  Row r;
  r["hash"] = "1:jQgCxbku+pNGw8WPbEc/TS/uTpQ=";

  SQL sql =
      SQL("SELECT community_id_v1('192.168.170.8', '192.168.170.56', 7, 80, "
          "132, 0) AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  sql =
      SQL("SELECT community_id_v1('192.168.170.56', '192.168.170.8', 80, 7, "
          "132, 0) AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  r["hash"] = "1:Y1/0jQg6e+I3ZwZZ9LP65DNbTXU=";

  sql =
      SQL("SELECT community_id_v1('192.168.170.8', '192.168.170.56', 7, 80, "
          "132, 1) AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  sql =
      SQL("SELECT community_id_v1('192.168.170.56', '192.168.170.8', 80, 7, "
          "132, 1) AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);
}

TEST_F(SQLiteHashingTests, test_community_id_v1_udp) {
  Row r;
  r["hash"] = "1:d/FP5EW3wiY1vCndhwleRRKHowQ=";

  SQL sql =
      SQL("SELECT community_id_v1('192.168.1.52', '8.8.8.8', 54585, 53, 17, 0) "
          "AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  sql =
      SQL("SELECT community_id_v1('8.8.8.8', '192.168.1.52', 53, 54585, 17, 0) "
          "AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  r["hash"] = "1:Q9We8WO3piVF8yEQBNJF4uiSVrI=";

  sql =
      SQL("SELECT community_id_v1('192.168.1.52', '8.8.8.8', 54585, 53, 17, 1) "
          "AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  sql =
      SQL("SELECT community_id_v1('8.8.8.8', '192.168.1.52', 53, 54585, 17, 1) "
          "AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);
}

TEST_F(SQLiteHashingTests, test_community_id_v1_strict) {
  SQL sql =
      SQL("SELECT community_id_v1_strict('192.168.1.52', 'foo', 10, 53, 17, 0) "
          "AS hash");
  EXPECT_FALSE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 0U);

  sql =
      SQL("SELECT community_id_v1_strict('192.168.1.52', '192.168.1.1', 10, "
          "53, 17, "
          "100000000) AS hash");
  EXPECT_FALSE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 0U);
}

TEST_F(SQLiteHashingTests, test_community_id_v1_nulls) {
  Row r;
  r["hash"] = "";

  SQL sql = SQL(
      "SELECT community_id_v1('192.168.1.52', 'foo', 10, 53, 17, 0) AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

  sql =
      SQL("SELECT community_id_v1('192.168.1.52', '192.168.1.1', 10, 53, 17, "
          "100000000) AS hash");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);
}
} // namespace osquery
