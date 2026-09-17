/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for gpu_info
// Spec file: specs/posix/gpu_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class gpuInfo : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(gpuInfo, test_sanity) {
  auto const data = execute_query("select * from gpu_info");
  ValidationMap row_map = {
      {"device_id", NormalType},
      {"name", NormalType},
      {"vendor", NormalType},
      {"vendor_id", NormalType},
      {"model", NormalType},
      {"model_id", NormalType},
      {"driver", NormalType},
      {"vram", IntOrEmpty},
      {"pci_slot", NormalType},
      {"pci_class_id", NormalType},
#ifdef __APPLE__
      {"cores", IntOrEmpty},
      {"metal_support", NormalType},
#endif
#ifdef WIN32
      {"driver_version", NormalType},
      {"driver_date", IntOrEmpty},
#endif
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery