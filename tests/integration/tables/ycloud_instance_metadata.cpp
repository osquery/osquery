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

class ycloudInstanceMetadata : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(ycloudInstanceMetadata, test_sanity) {
  auto const data = execute_query("select * from ycloud_instance_metadata");
  if (!data.empty()) {
    ValidationMap row_map = {
        {"instance_id", NormalType},
        {"folder_id", NormalType},
        {"name", NormalType},
        {"description", NormalType},
        {"hostname", NormalType},
        {"zone", NormalType},
        {"ssh_public_key", NormalType},
        {"serial_port_enabled", NormalType},
    };
    validate_rows(data, row_map);
  }
}

} // namespace table_tests
} // namespace osquery