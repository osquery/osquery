/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <chrono>
#include <limits>
#include <thread>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/core/conversions.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include <osquery/tests/test_util.h>

#include <include/osquery/numeric_monitoring.h>

#include "osquery/numeric_monitoring/plugin_interface.h"

namespace fs = boost::filesystem;

namespace osquery {

namespace {
void testAggrTypeToStringAndBack(const monitoring::PreAggregationType& aggrType,
                                 const std::string& aggrTypeStrRepr) {
  auto str = to<std::string>(aggrType);
  EXPECT_EQ(str, aggrTypeStrRepr);

  auto bRet = tryTo<monitoring::PreAggregationType>(str);
  EXPECT_FALSE(bRet.isError());
  EXPECT_EQ(bRet.get(), aggrType);
}
} // namespace

GTEST_TEST(NumericMonitoringTests, PreAggregationTypeToStringAndBack) {
  testAggrTypeToStringAndBack(monitoring::PreAggregationType::None, "none");
  testAggrTypeToStringAndBack(monitoring::PreAggregationType::Sum, "sum");
  testAggrTypeToStringAndBack(monitoring::PreAggregationType::Min, "min");
  testAggrTypeToStringAndBack(monitoring::PreAggregationType::Max, "max");
}

GTEST_TEST(NumericMonitoringTests, PreAggregationTypeToStringRecall) {
  // let's make sure we have string representation for every PreAggregationType
  using UnderType = std::underlying_type<monitoring::PreAggregationType>::type;
  const auto upper_limit = static_cast<UnderType>(
      monitoring::PreAggregationType::InvalidTypeUpperLimit);
  for (auto i = UnderType{}; i < upper_limit; ++i) {
    auto e = static_cast<monitoring::PreAggregationType>(i);
    EXPECT_FALSE(to<std::string>(e).empty());
  }
}

DECLARE_bool(enable_numeric_monitoring);
DECLARE_string(numeric_monitoring_plugins);
DECLARE_uint64(numeric_monitoring_pre_aggregation_time);

const auto name_for_test_plugin =
    "test_plugin_osquery/numeric_monitoring/tests/numeric_monitoring_tests";

class NumericMonitoringInMemoryTestPlugin : public NumericMonitoringPlugin {
 public:
  Status call(const PluginRequest& request, PluginResponse& response) override {
    NumericMonitoringInMemoryTestPlugin::points.push_back(request);
    return Status::success();
  }

  static std::vector<PluginRequest> points;
};

std::vector<PluginRequest> NumericMonitoringInMemoryTestPlugin::points;

REGISTER(NumericMonitoringInMemoryTestPlugin,
         monitoring::registryName(),
         name_for_test_plugin);

GTEST_TEST(NumericMonitoringTests, record_with_buffer) {
  const auto isEnabled = FLAGS_enable_numeric_monitoring;
  const auto plugins = FLAGS_numeric_monitoring_plugins;
  const auto pre_aggregation_time =
      FLAGS_numeric_monitoring_pre_aggregation_time;

  FLAGS_enable_numeric_monitoring = true;
  FLAGS_numeric_monitoring_plugins = name_for_test_plugin;
  FLAGS_numeric_monitoring_pre_aggregation_time = 1;

  monitoring::reset();
  NumericMonitoringInMemoryTestPlugin::points.clear();

  auto status = RegistryFactory::get().setActive(
      monitoring::registryName(), FLAGS_numeric_monitoring_plugins);
  ASSERT_TRUE(status.ok());
  const auto monitoring_path = "some.path.to.heaven";
  monitoring::record(monitoring_path,
                     monitoring::ValueType{83},
                     monitoring::PreAggregationType::Sum);
  monitoring::record(monitoring_path,
                     monitoring::ValueType{88},
                     monitoring::PreAggregationType::Sum);
  monitoring::record(monitoring_path,
                     monitoring::ValueType{93},
                     monitoring::PreAggregationType::Sum);
  std::this_thread::sleep_for(std::chrono::seconds(2));

  EXPECT_EQ(1, NumericMonitoringInMemoryTestPlugin::points.size());
  EXPECT_EQ(monitoring_path,
            NumericMonitoringInMemoryTestPlugin::points.back().at(
                monitoring::recordKeys().path));
  auto valueInStr = NumericMonitoringInMemoryTestPlugin::points.back().at(
      monitoring::recordKeys().value);
  EXPECT_EQ(83 + 88 + 93, std::stoll(valueInStr));

  FLAGS_enable_numeric_monitoring = isEnabled;
  FLAGS_numeric_monitoring_plugins = plugins;
  FLAGS_numeric_monitoring_pre_aggregation_time = pre_aggregation_time;
}

GTEST_TEST(NumericMonitoringTests, record_without_buffer) {
  const auto isEnabled = FLAGS_enable_numeric_monitoring;
  const auto plugins = FLAGS_numeric_monitoring_plugins;
  const auto pre_aggregation_time =
      FLAGS_numeric_monitoring_pre_aggregation_time;

  FLAGS_enable_numeric_monitoring = true;
  FLAGS_numeric_monitoring_plugins = name_for_test_plugin;
  FLAGS_numeric_monitoring_pre_aggregation_time = 0;

  monitoring::reset();
  NumericMonitoringInMemoryTestPlugin::points.clear();

  auto status = RegistryFactory::get().setActive(
      monitoring::registryName(), FLAGS_numeric_monitoring_plugins);
  ASSERT_TRUE(status.ok());
  const auto monitoring_path = "some.path.to.heaven";
  monitoring::record(monitoring_path,
                     monitoring::ValueType{146},
                     monitoring::PreAggregationType::Sum);
  monitoring::record(monitoring_path,
                     monitoring::ValueType{149},
                     monitoring::PreAggregationType::Sum);
  monitoring::record(monitoring_path,
                     monitoring::ValueType{152},
                     monitoring::PreAggregationType::Sum);
  std::this_thread::sleep_for(std::chrono::seconds(2));

  EXPECT_EQ(3, NumericMonitoringInMemoryTestPlugin::points.size());
  EXPECT_EQ(monitoring_path,
            NumericMonitoringInMemoryTestPlugin::points.back().at(
                monitoring::recordKeys().path));
  auto fristValueInStr = NumericMonitoringInMemoryTestPlugin::points.front().at(
      monitoring::recordKeys().value);
  EXPECT_EQ(146, std::stoll(fristValueInStr));

  auto lastValueInStr = NumericMonitoringInMemoryTestPlugin::points.back().at(
      monitoring::recordKeys().value);
  EXPECT_EQ(152, std::stoll(lastValueInStr));

  FLAGS_enable_numeric_monitoring = isEnabled;
  FLAGS_numeric_monitoring_plugins = plugins;
  FLAGS_numeric_monitoring_pre_aggregation_time = pre_aggregation_time;
}

} // namespace osquery
