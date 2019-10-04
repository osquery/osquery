/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for memory_map
// Spec file: specs/linux/memory_map.table

#include <osquery/utils/conversions/tryto.h>

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class MemoryMapTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(MemoryMapTest, test_sanity) {
  QueryData data = execute_query("select * from memory_map");
  ASSERT_GT(data.size(), 0ul);
  ValidatatioMap row_map = {{"name", NonEmptyString},
                            {"start", NonNegativeInt},
                            {"end", NonNegativeInt}};
  validate_rows(data, row_map);

  for (const auto& row : data) {
    auto start = tryTo<unsigned long long>(row.at("start"));
    auto end = tryTo<unsigned long long>(row.at("end"));
    ASSERT_TRUE(start) << "start does not fit in unsigned long long";
    ASSERT_TRUE(end) << "end does not fit in unsigned long long";
    ASSERT_LE(*start, *end) << "start should be less than or equal to end";
  }
}

} // namespace table_tests
} // namespace osquery
