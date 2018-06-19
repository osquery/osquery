/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/numeric_monitoring/plugins/filesystem.h>

#include <osquery/core/conversions.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include <osquery/tests/test_util.h>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

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

TEST_F(NumericMonitoringFilesystemPluginTests, init) {
  const auto log_path =
      fs::temp_directory_path() /
      fs::unique_path(
          "osquery.numeric_monitoring_filesystem_plugin_test.%%%%-%%%%.log");
  fs::remove(log_path); // in case it is already exists for some reason
  FLAGS_numeric_monitoring_filesystem_path = log_path.string();

  NumericMonitoringFilesystemPlugin plugin{};
  ASSERT_FALSE(plugin.isSetUp());
  ASSERT_TRUE(plugin.setUp().ok());
  ASSERT_TRUE(plugin.isSetUp());
  const auto path = R"path(p !"#$%&'()*+,-./0127:;<=>?@0AZ[\]^_`4bcyz{|}~)path";
  const auto value = double{1.5};
  const auto tm = int{1051};
  const auto request = PluginRequest{
      {monitoring::recordKeys().path, path},
      {monitoring::recordKeys().value, std::to_string(value)},
      {monitoring::recordKeys().timestamp, std::to_string(tm)},
  };
  auto response = PluginResponse{};
  EXPECT_TRUE(plugin.call(request, response).ok());
  EXPECT_TRUE(plugin.call(request, response).ok());

  ASSERT_TRUE(fs::exists(log_path));
  ASSERT_FALSE(fs::is_empty(log_path));

  auto fin = std::ifstream(log_path.native(), std::ios::in | std::ios::binary);
  auto line = std::string{};

  std::getline(fin, line);
  auto first_line = split(line, "\t");
  EXPECT_EQ(first_line.size(), 3);
  EXPECT_EQ(first_line[0], path);
  EXPECT_NEAR(std::stod(first_line[1]), value, 0.00001);
  EXPECT_EQ(std::stol(first_line[2]), tm);

  std::getline(fin, line);
  auto second_line = split(line, "\t");
  EXPECT_EQ(second_line.size(), 3);
  EXPECT_EQ(second_line[0], path);
  EXPECT_NEAR(std::stod(second_line[1]), value, 0.00001);
  EXPECT_EQ(std::stol(second_line[2]), tm);

  fs::remove(log_path);
}

} // namespace osquery
