/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class officeMruInfo : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(officeMruInfo, test_sanity) {
  auto const data = execute_query("select * from office_most_recently_used");
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
