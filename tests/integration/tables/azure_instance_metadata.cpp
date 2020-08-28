/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class azureInstanceMetadata : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(azureInstanceMetadata, test_sanity) {
  auto const data = execute_query("select * from azure_instance_metadata");
  if (!data.empty()) {
    ValidationMap row_map = {
        {"location", NormalType},
        {"name", NormalType},
        {"architecture", NormalType},
        {"offer", NormalType},
        {"publisher", NormalType},
        {"sku", NormalType} {"version", NormalType},
        {"os_type", NormalType},
        {"platform_update_domain", NormalType},
        {"platform_fault_domain", NormalType},
        {"vm_id", NormalType},
        {"vm_size", NormalType},
        {"subscription_id", NormalType},
        {"resource_group_name", NormalType},
        {"placement_group_id", NormalType},
        {"vm_scale_set_name", NormalType},
        {"zone", NormalType},
    };
    validate_rows(data, row_map);
  }

} // namespace table_tests
} // namespace table_tests
