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

class azureInstanceTags : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(azureInstanceTags, test_sanity) {
  auto const data = execute_query("select * from azure_instance_tags");
  if (!data.empty()) {
    ValidationMap row_map = {
        {"vm_id", NormalType},
        {"key", NormalType},
        {"value", NormalType},
    };
    validate_rows(data, row_map);
  }
}

} // namespace table_tests
} // namespace osquery
