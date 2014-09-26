// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/sql.h"

#include <gtest/gtest.h>

#include "osquery/core.h"

namespace osquery {

class SQLTests : public testing::Test {};

TEST_F(SQLTests, test_simple_query_execution) {
  auto sql = SQL("SELECT * FROM time");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.getMessageString(), getStringForSQLiteReturnCode(0));
  EXPECT_EQ(sql.rows().size(), 1);
}

TEST_F(SQLTests, test_get_tables) {
  auto tables = SQL::getTableNames();
  EXPECT_TRUE(tables.size() > 0);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  osquery::initOsquery(argc, argv);
  return RUN_ALL_TESTS();
}
