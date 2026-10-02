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
#include <osquery/utils/info/platform_type.h>

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
    GTEST_SKIP() << "gpu_metrics returned no rows";
  }

  ValidationMap row_map = {
      {"gpu_index", NonNegativeInt},
      {"vendor_name", NormalType},
      {"device_name", NormalType},
      {"driver_version", NormalType},
      {"vram_total_bytes", IntOrEmpty},
      {"gpu_utilization_pct", NormalType},
  };

  if (isPlatform(PlatformType::TYPE_POSIX)) {
    row_map.emplace("pci_bus", NormalType);
    row_map.emplace("power_draw_watts", NormalType);
  }

  if (isPlatform(PlatformType::TYPE_OSX)) {
    row_map.emplace("total_cores", IntOrEmpty);
    row_map.emplace("allocated_vram", IntOrEmpty);
    row_map.emplace("in_use_vram", IntOrEmpty);
  }

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    row_map.emplace("temperature_gpu_celsius", NormalType);
    row_map.emplace("power_limit_watts", NormalType);
    row_map.emplace("fan_speed_pct", NormalType);
  }

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
