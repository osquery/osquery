/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/tables.h>

namespace osquery {
namespace tables {

class TablesTests : public testing::Test {};

TEST_F(TablesTests, test_constraint) {
  auto constraint = Constraint(EQUALS);
  constraint.expr = "none";

  EXPECT_EQ(constraint.op, EQUALS);
  EXPECT_EQ(constraint.expr, "none");
}

TEST_F(TablesTests, test_constraint_list) {
  struct ConstraintList cl;

  auto constraint = Constraint(EQUALS);
  constraint.expr = "some";

  // The constraint list is a simple struct.
  cl.add(constraint);
  EXPECT_EQ(cl.constraints_.size(), 1);

  constraint = Constraint(EQUALS);
  constraint.expr = "some_other";
  cl.add(constraint);

  constraint = Constraint(GREATER_THAN);
  constraint.expr = "more_than";
  cl.add(constraint);
  EXPECT_EQ(cl.constraints_.size(), 3);

  auto all_equals = cl.getAll(EQUALS);
  EXPECT_EQ(all_equals.size(), 2);
}

TEST_F(TablesTests, test_constraint_matching) {
  struct ConstraintList cl;
  // An empty constraint list has expectations.
  EXPECT_FALSE(cl.exists());
  EXPECT_TRUE(cl.notExistsOrMatches("some"));

  auto constraint = Constraint(EQUALS);
  constraint.expr = "some";
  cl.add(constraint);

  EXPECT_TRUE(cl.exists());
  EXPECT_TRUE(cl.notExistsOrMatches("some"));
  EXPECT_TRUE(cl.matches("some"));
  EXPECT_FALSE(cl.notExistsOrMatches("not_some"));

  struct ConstraintList cl2;
  cl2.affinity = "INTEGER";
  constraint = Constraint(LESS_THAN);
  constraint.expr = "1000";
  cl2.add(constraint);
  constraint = Constraint(GREATER_THAN);
  constraint.expr = "1";
  cl2.add(constraint);

  // Test both SQL-provided string types.
  EXPECT_TRUE(cl2.matches("10"));
  // ...and the type literal.
  EXPECT_TRUE(cl2.matches(10));

  // Test operator lower bounds.
  EXPECT_FALSE(cl2.matches(0));
  EXPECT_FALSE(cl2.matches(1));

  // Test operator upper bounds.
  EXPECT_FALSE(cl2.matches(1000));
  EXPECT_FALSE(cl2.matches(1001));

  // Now test inclusive bounds.
  struct ConstraintList cl3;
  constraint = Constraint(LESS_THAN_OR_EQUALS);
  constraint.expr = "1000";
  cl3.add(constraint);
  constraint = Constraint(GREATER_THAN_OR_EQUALS);
  constraint.expr = "1";
  cl3.add(constraint);

  EXPECT_FALSE(cl3.matches(1001));
  EXPECT_TRUE(cl3.matches(1000));

  EXPECT_FALSE(cl3.matches(0));
  EXPECT_TRUE(cl3.matches(1));
}

TEST_F(TablesTests, test_constraint_map) {
  ConstraintMap cm;
  ConstraintList cl;

  cl.add(Constraint(EQUALS, "some"));
  cm["path"] = cl;

  EXPECT_TRUE(cm["path"].matches("some"));
}

TEST_F(TablesTests, test_get_query_columns) {
  std::unique_ptr<sqlite3, decltype(sqlite3_close)*> db_managed(createDB(),
                                                                sqlite3_close);
  sqlite3* db = db_managed.get();

  std::string query;
  Status status;
  TableColumns results;

  query =
      "SELECT hour, minutes, seconds, version, config_md5, config_path, \
           pid FROM time JOIN osquery_info";
  status = getQueryColumns(query, results, db);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(7, results.size());
  EXPECT_EQ(std::make_pair(std::string("hour"), std::string("INTEGER")),
            results[0]);
  EXPECT_EQ(std::make_pair(std::string("minutes"), std::string("INTEGER")),
            results[1]);
  EXPECT_EQ(std::make_pair(std::string("seconds"), std::string("INTEGER")),
            results[2]);
  EXPECT_EQ(std::make_pair(std::string("version"), std::string("TEXT")),
            results[3]);
  EXPECT_EQ(std::make_pair(std::string("config_md5"), std::string("TEXT")),
            results[4]);
  EXPECT_EQ(std::make_pair(std::string("config_path"), std::string("TEXT")),
            results[5]);
  EXPECT_EQ(std::make_pair(std::string("pid"), std::string("INTEGER")),
            results[6]);

  query = "SELECT hour + 1 AS hour1, minutes + 1 FROM time";
  status = getQueryColumns(query, results, db);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(2, results.size());
  EXPECT_EQ(std::make_pair(std::string("hour1"), std::string("UNKNOWN")),
            results[0]);
  EXPECT_EQ(std::make_pair(std::string("minutes + 1"), std::string("UNKNOWN")),
            results[1]);

  query = "SELECT * FROM foo";
  status = getQueryColumns(query, results, db);
  ASSERT_FALSE(status.ok());
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  osquery::initOsquery(argc, argv);
  return RUN_ALL_TESTS();
}
