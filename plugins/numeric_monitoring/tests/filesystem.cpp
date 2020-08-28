/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/core/flags.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <plugins/numeric_monitoring/filesystem.h>

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_string(numeric_monitoring_filesystem_path);

class NumericMonitoringFilesystemPluginTests : public testing::Test {
 public:
  void SetUp() override {
    old_flag_value_ = FLAGS_numeric_monitoring_filesystem_path;
  }

  void TearDown() override {
    FLAGS_numeric_monitoring_filesystem_path = old_flag_value_;
  }

 protected:
  std::string old_flag_value_;
};

TEST_F(NumericMonitoringFilesystemPluginTests, simple_workflow) {
  const auto log_path =
      fs::temp_directory_path() /
      fs::unique_path(
          "osquery.numeric_monitoring_filesystem_plugin_test.%%%%-%%%%%%.log");
  FLAGS_numeric_monitoring_filesystem_path = log_path.string();
  {
    NumericMonitoringFilesystemPlugin plugin{};
    ASSERT_FALSE(plugin.isSetUp());
    ASSERT_TRUE(plugin.setUp().ok());
    ASSERT_TRUE(plugin.isSetUp());
    const auto path =
        R"path(p !"#$%&'()*+,-./0127:;<=>?@0AZ[\]^_`4bcyz{|}~)path";
    const auto value = double{1.5};
    const auto tm = int{1051};
    const auto sync = true;
    const auto request = PluginRequest{
        {monitoring::recordKeys().path, path},
        {monitoring::recordKeys().value, std::to_string(value)},
        {monitoring::recordKeys().timestamp, std::to_string(tm)},
        {monitoring::recordKeys().sync, sync ? "true" : "false"},
    };
    auto response = PluginResponse{};
    EXPECT_TRUE(plugin.call(request, response).ok());
    EXPECT_TRUE(plugin.call(request, response).ok());

    ASSERT_TRUE(fs::exists(log_path));
    ASSERT_FALSE(fs::is_empty(log_path));

    auto fin =
        std::ifstream(log_path.native(), std::ios::in | std::ios::binary);
    auto line = std::string{};

    {
      std::getline(fin, line);
      auto first_line = split(line, "\t");
      EXPECT_EQ(first_line.size(), request.size());
      EXPECT_EQ(first_line[0], path);
      EXPECT_NEAR(std::stod(first_line[1]), value, 0.00001);
      EXPECT_EQ(std::stol(first_line[2]), tm);
      const auto sync_extracted = tryTo<bool>(first_line[3]);
      EXPECT_TRUE(sync_extracted);
      EXPECT_EQ(*sync_extracted, sync);
    }
    {
      std::getline(fin, line);
      auto second_line = split(line, "\t");
      EXPECT_EQ(second_line.size(), request.size());
      EXPECT_EQ(second_line[0], path);
      EXPECT_NEAR(std::stod(second_line[1]), value, 0.00001);
      EXPECT_EQ(std::stol(second_line[2]), tm);
      const auto sync_extracted = tryTo<bool>(second_line[3]);
      EXPECT_TRUE(sync_extracted);
      EXPECT_EQ(*sync_extracted, sync);
    }
  }
  fs::remove(log_path);
}

} // namespace osquery
