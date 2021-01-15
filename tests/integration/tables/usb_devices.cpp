/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for usb_devices
// Spec file: specs/posix/usb_devices.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class usbDevices : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(usbDevices, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from usb_devices");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for available flags
  // Or use custom DataCheck object
  // ValidationMap row_map = {
  //      {"usb_address", IntType}
  //      {"usb_port", IntType}
  //      {"vendor", NormalType}
  //      {"vendor_id", NormalType}
  //      {"version", NormalType}
  //      {"model", NormalType}
  //      {"model_id", NormalType}
  //      {"serial", NormalType}
  //      {"class", NormalType}
  //      {"subclass", NormalType}
  //      {"protocol", NormalType}
  //      {"removable", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
