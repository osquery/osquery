
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for pci_devices
// Spec file: specs/posix/pci_devices.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class pciDevices : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(pciDevices, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from pci_devices");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"pci_slot", NormalType}
  //      {"pci_class", NormalType}
  //      {"driver", NormalType}
  //      {"vendor", NormalType}
  //      {"vendor_id", NormalType}
  //      {"model", NormalType}
  //      {"model_id", NormalType}
  //      {"subsystem_vendor_id", NormalType}
  //      {"subsystem_vendor", NormalType}
  //      {"subsystem_model_id", NormalType}
  //      {"subsystem_model", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
