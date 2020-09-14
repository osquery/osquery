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
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/numeric_monitoring/numeric_monitoring.h>
#include <osquery/registry/registry_factory.h>

#include <osquery/utils/conversions/tryto.h>

#include <osquery/numeric_monitoring/plugin_interface.h>

namespace fs = boost::filesystem;

namespace osquery {

class NumericMonitoringTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

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

TEST_F(NumericMonitoringTests, PreAggregationTypeToStringAndBack) {
  testAggrTypeToStringAndBack(monitoring::PreAggregationType::None, "none");
  testAggrTypeToStringAndBack(monitoring::PreAggregationType::Sum, "sum");
  testAggrTypeToStringAndBack(monitoring::PreAggregationType::Min, "min");
  testAggrTypeToStringAndBack(monitoring::PreAggregationType::Max, "max");
}

TEST_F(NumericMonitoringTests, PreAggregationTypeToStringRecall) {
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

const auto kNameForTestPlugin =
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
         kNameForTestPlugin);

TEST_F(NumericMonitoringTests, record_with_buffer) {
  const auto isEnabled = FLAGS_enable_numeric_monitoring;
  const auto plugins = FLAGS_numeric_monitoring_plugins;
  const auto pre_aggregation_time =
      FLAGS_numeric_monitoring_pre_aggregation_time;

  FLAGS_enable_numeric_monitoring = true;
  FLAGS_numeric_monitoring_plugins = kNameForTestPlugin;
  FLAGS_numeric_monitoring_pre_aggregation_time = 1;

  auto status = RegistryFactory::get().setActive(
      monitoring::registryName(), FLAGS_numeric_monitoring_plugins);
  ASSERT_TRUE(status.ok());

  monitoring::flush();
  NumericMonitoringInMemoryTestPlugin::points.clear();

  const auto monitoring_path = "some.path.to.heaven";
  monitoring::record(monitoring_path,
                     monitoring::ValueType{83},
                     monitoring::PreAggregationType::Sum,
                     false);
  monitoring::record(monitoring_path,
                     monitoring::ValueType{84},
                     monitoring::PreAggregationType::Sum,
                     true);
  monitoring::record(monitoring_path,
                     monitoring::ValueType{88},
                     monitoring::PreAggregationType::Sum);
  monitoring::record(monitoring_path,
                     monitoring::ValueType{93},
                     monitoring::PreAggregationType::Sum);
  monitoring::flush();

  EXPECT_EQ(2, NumericMonitoringInMemoryTestPlugin::points.size());
  EXPECT_EQ(monitoring_path,
            NumericMonitoringInMemoryTestPlugin::points.back().at(
                monitoring::recordKeys().path));
  auto valueInStr = NumericMonitoringInMemoryTestPlugin::points.back().at(
      monitoring::recordKeys().value);
  EXPECT_EQ(83 + 88 + 93, std::stoll(valueInStr));

  FLAGS_enable_numeric_monitoring = isEnabled;
  FLAGS_numeric_monitoring_plugins = plugins;
  FLAGS_numeric_monitoring_pre_aggregation_time = pre_aggregation_time;

  Dispatcher::stopServices();
  Dispatcher::joinServices();
}

TEST_F(NumericMonitoringTests, record_without_buffer) {
  const auto isEnabled = FLAGS_enable_numeric_monitoring;
  const auto plugins = FLAGS_numeric_monitoring_plugins;
  const auto pre_aggregation_time =
      FLAGS_numeric_monitoring_pre_aggregation_time;

  FLAGS_enable_numeric_monitoring = true;
  FLAGS_numeric_monitoring_plugins = kNameForTestPlugin;
  FLAGS_numeric_monitoring_pre_aggregation_time = 0;

  monitoring::flush();
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

  // pay attention there is no flush

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

  Dispatcher::stopServices();
  Dispatcher::joinServices();
}

} // namespace osquery
