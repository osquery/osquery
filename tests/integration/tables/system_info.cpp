/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for system_info
// Spec file: specs/system_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class SystemInfo : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(SystemInfo, test_sanity) {
  QueryData data = execute_query("select * from system_info");
  ASSERT_EQ(data.size(), 1ul);
  ValidationMap row_map = {{"hostname", NormalType},
                           {"uuid", ValidUUID},
                           {"cpu_type", NonEmptyString},
                           {"cpu_subtype", NormalType},
                           {"cpu_brand", NormalType},
                           {"cpu_physical_cores", NonNegativeInt},
                           {"cpu_logical_cores", NonNegativeInt},
                           {"cpu_microcode", NormalType},
                           {"physical_memory", NonNegativeInt},
                           {"hardware_vendor", NormalType},
                           {"hardware_model", NormalType},
                           {"hardware_version", NormalType},
                           {"hardware_serial", NormalType},
                           {"board_vendor", NormalType},
                           {"board_model", NormalType},
                           {"board_version", NormalType},
                           {"board_serial", NormalType},
                           {"computer_name", NormalType},
                           {"local_hostname", NonEmptyString}};
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
