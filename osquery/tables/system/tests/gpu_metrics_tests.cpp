/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <set>

#include <gtest/gtest.h>

#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>

namespace osquery {
namespace tables {

class GpuMetricsTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

TEST_F(GpuMetricsTests, test_schema) {
  // The query must succeed and return the expected columns without crashing.
  SQL results(
      "select gpu_index, pci_bus, vendor_name, device_name, driver_version, "
      "vram_total_bytes from gpu_metrics");

  EXPECT_TRUE(results.ok());

  if (results.rows().empty()) {
    // No GPU detected in this environment; nothing further to check.
    return;
  }

  for (const auto& row : results.rows()) {
    EXPECT_EQ(row.count("gpu_index"), 1U);
    EXPECT_EQ(row.count("pci_bus"), 1U);
    EXPECT_EQ(row.count("vendor_name"), 1U);
    EXPECT_EQ(row.count("device_name"), 1U);
    EXPECT_EQ(row.count("driver_version"), 1U);
    EXPECT_EQ(row.count("vram_total_bytes"), 1U);
  }
}

TEST_F(GpuMetricsTests, test_gpu_index_is_non_negative) {
  SQL results("select gpu_index from gpu_metrics");

  for (const auto& row : results.rows()) {
    int idx = std::stoi(row.at("gpu_index"));
    EXPECT_GE(idx, 0);
  }
}

TEST_F(GpuMetricsTests, test_gpu_index_is_unique) {
  SQL results("select gpu_index from gpu_metrics");

  std::set<std::string> seen;
  for (const auto& row : results.rows()) {
    const auto& idx = row.at("gpu_index");
    EXPECT_TRUE(seen.insert(idx).second)
        << "Duplicate gpu_index value: " << idx;
  }
}

TEST_F(GpuMetricsTests, test_device_name_non_empty) {
  SQL results("select device_name from gpu_metrics");

  for (const auto& row : results.rows()) {
    EXPECT_FALSE(row.at("device_name").empty())
        << "device_name should not be empty for a detected GPU";
  }
}

} // namespace tables
} // namespace osquery
