/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/database/database.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {
class UnifiedLogTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

typedef struct DeltaContext {
  double timestamp;
  unsigned int count;

  DeltaContext() : timestamp(0), count(0) {}

  void load() {
    std::string str;
    auto s = getDatabaseValue(kPersistentSettings, "ual_timestamp", str);
    if (s.ok())
      timestamp = std::stod(str);
    s = getDatabaseValue(kPersistentSettings, "ual_counter", str);
    if (s.ok())
      count = std::stod(str);
  }

  bool operator<(const DeltaContext& dc2) {
    return timestamp < dc2.timestamp || count < dc2.count;
  }
} DeltaContext;

TEST_F(UnifiedLogTest, test_sanity) {
  QueryData const rows =
      execute_query("select * from unified_log where pid > 100 and pid < 105");

  ASSERT_GT(rows.size(), 0ul);

  ValidationMap row_map = {
      {"timestamp", IntType},
      {"level", NormalType},
      {"storage", IntType},
      {"message", NormalType},
      {"activity", IntType},
      {"process", NormalType},
      {"pid", IntType},
      {"sender", NormalType},
      {"tid", IntType},
      {"category", NormalType},
      {"subsystem", NormalType},
  };
  validate_rows(rows, row_map);

  // max rows test
  QueryData const r1 =
      execute_query("select * from unified_log where max_rows = 50");
  ASSERT_EQ(r1.size(), 50ul);
  QueryData const r2 =
      execute_query("select * from unified_log where max_rows = 1");
  ASSERT_EQ(r2.size(), 1ul);
  QueryData const r3 =
      execute_query("select * from unified_log where max_rows = 0");
  ASSERT_EQ(r3.size(), 0ul);
  QueryData const r4 =
      execute_query("select * from unified_log where max_rows = -1");
  ASSERT_EQ(r4.size(), 0ul);

  // Sequential test: checks the pointer is increased and the data extracted
  //                  is different
  DeltaContext dc1, dc2;
  dc1.load();
  QueryData const r5 = execute_query(
      "select * from unified_log where max_rows = 1 and timestamp > -1");
  dc2.load();
  EXPECT_TRUE(dc1 < dc2);
  QueryData const r6 = execute_query(
      "select * from unified_log where max_rows = 1 and timestamp > -1");
  ASSERT_EQ(r5.size(), 1ul);
  ASSERT_EQ(r6.size(), 1ul);
  bool sequential_queries_diff = false;
  for (auto it = r5[0].begin(); it != r5[0].end(); it++) {
    if (it->second != r6[0].at(it->first)) {
      sequential_queries_diff = true;
      break;
    }
  }
  EXPECT_TRUE(sequential_queries_diff);
}
} // namespace table_tests
} // namespace osquery