/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for iptables
// Spec file: specs/linux/iptables.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class iptables : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(iptables, test_sanity) {
  auto const data = execute_query("select * from iptables");

  ASSERT_GE(data.size(), 0ul);

  ValidationMap row_map = {{"filter_name", NonEmptyString},
                           {"chain", NormalType},
                           {"policy", NormalType},
                           {"target", NormalType},
                           {"protocol", IntType},
                           {"src_port", IntMinMaxCheck(0, 65535)},
                           {"dst_port", IntMinMaxCheck(0, 65535)},
                           {"src_ip", verifyEmptyStringOrIpAddress},
                           {"src_mask", verifyEmptyStringOrIpAddress},
                           {"iniface", NormalType},
                           {"iniface_mask", verifyEmptyStringOrIpAddress},
                           {"dst_ip", verifyEmptyStringOrIpAddress},
                           {"dst_mask", verifyEmptyStringOrIpAddress},
                           {"outiface", NormalType},
                           {"outiface_mask", verifyEmptyStringOrIpAddress},
                           {"match", SpecificValuesCheck{"yes", "no"}},
                           {"packets", NonNegativeInt},
                           {"bytes", NonNegativeInt}};
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
