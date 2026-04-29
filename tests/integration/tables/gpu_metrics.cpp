/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for gpu_metrics
// Spec file: specs/gpu_metrics.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class gpuMetrics : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(gpuMetrics, test_sanity) {
  auto const data = execute_query("select * from gpu_metrics");

  // GPUs may not be present in all test environments; skip validation if empty.
  if (data.empty()) {
    return;
  }

  ValidationMap row_map = {
      {"gpu_index", NonNegativeInt},
      {"pci_bus", NormalType},
      {"vendor_name", NormalType},
      {"device_name", NonEmptyString},
      {"total_cores", IntOrEmpty},
      {"driver_version", NormalType},
      // vram_total_bytes, gpu_utilization_pct, temperature_gpu_celsius,
      // power_draw_watts, power_limit_watts, fan_speed_pct are all optional
      // (NULL when not supported by the platform/driver).
      {"vram_total_bytes", IntOrEmpty},
      {"allocated_vram", IntOrEmpty},
      {"in_use_vram", IntOrEmpty},
      {"gpu_utilization_pct", IntOrEmpty},
      {"temperature_gpu_celsius", IntOrEmpty},
      {"power_draw_watts", IntOrEmpty},
      {"power_limit_watts", IntOrEmpty},
      {"fan_speed_pct", IntOrEmpty},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
