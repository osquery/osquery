/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for wmi_tpm_info
// Spec file: specs/windows/wmi_script_event_consumers.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class wmiTpmInfo : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(wmiTpmInfo, test_sanity) {
  auto const data = execute_query("select * from wmi_tpm_info");
}

} // namespace table_tests
} // namespace osquery
